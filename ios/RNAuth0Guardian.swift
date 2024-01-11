//
//  RNAuth0Guardian.swift
//  RNAuth0Guardian
//
//  Created by Mukhammad Ali on 2020/01/07.
//  Copyright © 2020. All rights reserved.
//

import Guardian

struct CustomEnrolledDevice: Codable {
  public let id: String
  public let userId: String
  public let deviceToken: String
  public let notificationToken: String
  public let secret: String?
  public let algorithm: HMACAlgorithm?
  public let digits: Int?
  public let period: Int?

  public init(
       id: String,
       userId: String,
       deviceToken: String,
       notificationToken: String,
       secret: String? = nil,
       algorithm: HMACAlgorithm? = nil,
       digits: Int? = nil,
       period: Int? = nil
      ) {
      self.id = id
      self.userId = userId
      self.deviceToken = deviceToken
      self.notificationToken = notificationToken
      self.secret = secret
      self.algorithm = algorithm
      self.digits = digits
      self.period = period
      
  }
  enum CodingKeys: String, CodingKey {
      case id
      case userId
      case deviceToken
      case notificationToken
      case secret
      case algorithm
      case digits
      case period
  }

  init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      id = try container.decode(String.self, forKey: .id)
      userId = try container.decode(String.self, forKey: .userId)
      deviceToken = try container.decode(String.self, forKey: .deviceToken)
      notificationToken = try container.decode(String.self, forKey: .notificationToken)
      secret = try container.decode(String.self, forKey: .secret)
      algorithm = try container.decode(HMACAlgorithm.self, forKey: .algorithm)
      digits = try container.decode(Int.self, forKey: .digits)
      period = try container.decode(Int.self, forKey: .period)
  }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(id, forKey: .id)
      try container.encode(userId, forKey: .userId)
      try container.encode(deviceToken, forKey: .deviceToken)
      try container.encode(notificationToken, forKey: .notificationToken)
      try container.encode(secret, forKey: .secret)
      try container.encode(algorithm, forKey: .algorithm)
      try container.encode(digits, forKey: .digits)
      try container.encode(period, forKey: .period)
    }
    
    func asJSONObject() throws -> Any  {
        let encoder = JSONEncoder()
        let encoded = try encoder.encode(self)
        let jsonObject = try JSONSerialization.jsonObject(with: encoded, options: [])
        return jsonObject
    }
}

extension UserDefaults {
   func save<T:Encodable>(customObject object: T, inKey key: String) {
       let encoder = JSONEncoder()
       if let encoded = try? encoder.encode(object) {
           self.set(encoded, forKey: key)
       }
   }
   func retrieve<T:Decodable>(object type:T.Type, fromKey key: String) -> T? {
       if let data = self.data(forKey: key) {
           let decoder = JSONDecoder()
           if let object = try? decoder.decode(type, from: data) {
               return object
           }else {
               print("Couldnt decode object")
               return nil
           }
       }else {
           print("Couldnt find key")
           return nil
       }
   }
}


enum CustomError: Error {
    case runtimeError(String)
}


@objc(RNAuth0Guardian)
class RNAuth0Guardian: NSObject {
    let AUTH0_DOMAIN = "AUTH0_DOMAIN"
    let ENROLLED_DEVICE = "ENROLLED_DEVICE"
    
    var domain: String?
    var enrolledDevice: [EnrolledDevice]?
    var customEnrolledDevice: [CustomEnrolledDevice]?
    var signingKey: KeychainRSAPrivateKey?
    
  
    override init() {
        super.init()
    }
    
    func getEnrollment(_ enrollmentId: String?) -> EnrolledDevice?{
        var enrollment: EnrolledDevice? = nil;
        if let unwrapped = enrollmentId, !unwrapped.isEmpty {
            enrollment = self.enrolledDevice?.first(where: {$0.id == enrollmentId})
        }else{
            enrollment = self.enrolledDevice?.first
        }
        return enrollment;
    }
    
    @objc
    func getEnrollments(resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock){
        do{
            let encoder = JSONEncoder()
            let encoded = try encoder.encode(self.customEnrolledDevice)
            let jsonObject = try JSONSerialization.jsonObject(with: encoded, options: [])
            resolve(jsonObject)
        }catch{
            reject("SIGNING_KEY", "SigningKey generation failed", error)
        }
    }
    
    @objc
    func initialize(_ auth0Domain: NSString,  resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) {
        let domain = auth0Domain as String
        let bundleID = Bundle.main.bundleIdentifier
        if domain.isEmpty {
            reject("DOMAIN_NULL", "Domain is null", nil)
        } else {
            self.domain = auth0Domain as String
            do {
                let signingKey = try KeychainRSAPrivateKey.new(with: bundleID!)
                self.signingKey = signingKey
                 if let retrievedData = UserDefaults.standard.retrieve(object: [CustomEnrolledDevice].self, fromKey: ENROLLED_DEVICE) ?? nil {
                     self.customEnrolledDevice = retrievedData
                     
                     self.enrolledDevice = self.customEnrolledDevice!.map {customEnrollment in
                         var totp: OTPParameters? = nil
                         if customEnrollment.secret != nil {
                             totp = OTPParameters(base32Secret: customEnrollment.secret!, algorithm: customEnrollment.algorithm, digits: customEnrollment.digits, period: customEnrollment.period)
                         }
                         return EnrolledDevice(id: customEnrollment.id, userId: customEnrollment.userId, deviceToken: customEnrollment.deviceToken, notificationToken: customEnrollment.notificationToken, signingKey: signingKey, totp: totp
                         )
                     }
                 }
                
                resolve(true)
            } catch {
                reject("SIGNING_KEY", "SigningKey generation failed", error)
            }
        }
    }
    @objc
    func getTOTP(_ enrollmentId: NSString?, resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock){
        
        if let enrollment = getEnrollment(enrollmentId as String?) {
            let totpInt: Int = try! Guardian.totp(parameters: enrollment.totp!).code();
            var totpString = String(totpInt)
            if(totpString.isEmpty == false && totpString.count <= 5) {
                for _ in 1...6 - totpString.count {
                    totpString = "0" + totpString
                }
            }
            resolve(totpString)
        } else {
            reject("DEVICE_NOT_ENRROLED", "Device is not enrolled yet!", nil)
        }
    }
  
    @objc
    func enroll(_ enrollmentURI: NSString, deviceToken: NSString, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock){
        let enrollmentUri = enrollmentURI as String
        let deviceTokenString = deviceToken as String
        do {
          let verificationKey = try signingKey!.verificationKey()
          
          if (deviceTokenString.isEmpty) {
            reject("DEVICE_TOKEN_NULL", "Device token is not provided", nil)
          } else if (enrollmentUri.isEmpty) {
            reject("ENROLLMENT_URI_NULL", "Enrollment URI from Qrcode is not provided", nil)
          } else {
            Guardian
                .enroll(forDomain: self.domain!,
                    usingUri: enrollmentUri,
                    notificationToken: deviceTokenString,
                    signingKey: signingKey!,
                    verificationKey: verificationKey
                    )
            .start { result in
                switch result {
                case .success(let enrolledDevice):
                    self.enrolledDevice?.append(enrolledDevice);
                    let customEnrollment = CustomEnrolledDevice(id: enrolledDevice.id, userId: enrolledDevice.userId, deviceToken: enrolledDevice.deviceToken, notificationToken: enrolledDevice.notificationToken, secret: enrolledDevice.totp?.base32Secret, algorithm: enrolledDevice.totp?.algorithm,  period: enrolledDevice.totp?.period, digits: enrolledDevice.totp?.digits
                    )
                    self.customEnrolledDevice?.append(customEnrollment);
                    UserDefaults.standard.save(customObject: self.customEnrolledDevice, inKey: self.ENROLLED_DEVICE)

                    resolve(customEnrollment.asJSONObject())
                    break
                case .failure(let cause):
                    print("ENROLL FAILED: ", cause)
                    reject("ENROLLMENT_FAILED", "Enrollment failed", cause)
                    break
                }
            }
          }
        } catch {
            reject("ENROLLMENT_FAILED", "Enrollment failed", error)
        }
    }
  
    @objc
    func allow(_ userInfo: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock){
        if (self.enrolledDevice != nil) {
            if let notification = Guardian.notification(from: userInfo as! [AnyHashable : Any]) {
                if let enrollment = getEnrollment(notification.enrollmentId){
                    Guardian
                      .authentication(forDomain: self.domain!, device: enrollment)
                      .allow(notification: notification)
                      .start { result in
                        switch result {
                        case .success:
                          resolve(true)
                          break
                        case .failure(let cause):
                          print("ALLOW FAILED!", cause)
                          reject("ALLOW_FAILED", "Allow failed", cause)
                          break
                        }
                      }
                }else{
                    print("ALLOW FAILED!", "Could not find enrollment")
                    reject("ALLOW_FAILED", "Allow failed!", "Could not find enrollment")
                }
              
            } else {
                 reject("NOTIFICATION_NULL", "Notification is not provided yet!", nil)
            }
        } else {
            reject("DEVICE_NOT_ENRROLED", "Device is not enrolled yet!", nil)
        }
    }
  
    @objc
    func reject(_ userInfo: [AnyHashable : Any], resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        if let notification = Guardian.notification(from: userInfo) {
            if let enrollment = getEnrollment(notification.enrollmentId){
                Guardian
                    .authentication(forDomain: self.domain!, device: enrollment)
                    .reject(notification: notification)
                    .start { result in
                         switch result {
                             case .success:
                               resolve(true)
                               break
                             case .failure(let cause):
                               print("REJECT FAILED!", cause)
                               reject("REJECT_FAILED", "Reject failed!" ,cause)
                               break
                         }
                    }
            }else{
                print("REJECT FAILED!", "Could not find enrollment")
                reject("REJECT_FAILED", "Reject failed!", "Could not find enrollment")
            }
            
        } else {
             reject("NOTIFICATION_NULL", "Notification is not provided yet!", nil)
        }
    }
  
    @objc
    func unenroll(_ enrollmentId: NSString?, resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
        if let enrollment = getEnrollment(enrollmentId as String?){
            Guardian
                .api(forDomain: self.domain!)
                .device(forEnrollmentId: enrollment.id, token: enrollment.deviceToken)
                .delete()
                .start { result in
                    switch result {
                    case .success:
                        self.enrolledDevice?.removeAll(where: {$0.id == enrollment?.id})
                        self.customEnrolledDevice?.removeAll(where: {$0.id == enrollment?.id})
                        UserDefaults.standard.save(customObject: self.customEnrolledDevice, inKey: self.ENROLLED_DEVICE)
                      resolve(true)
                      break
                    case .failure(let cause):
                      print("UNENROLL FAILED!", cause)
                      reject("UNENROLL_FAILED", "Unenroll failed!", cause)
                      break
                    }
                }
        }else{
            print("UNENROLL FAILED!", "Could not find enrollment")
            reject("UNENROLL_FAILED", "Unenroll failed!", "Could not find enrollment")
        }
        
    }
  
    @objc
    static func requiresMainQueueSetup() -> Bool {
        return true
    }
}

