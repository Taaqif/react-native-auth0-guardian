export type Enrollment = {
  id: string;
  userId: string;
  period: number;
  digits: number;
  algorithm: string;
  secret: string;
  deviceIdentifier: string;
  deviceName: string;
  deviceToken: string;
};

export type Aps = {
  alert: ApsAlert;
  category: string;
};

export type ApsAlert = {
  body: string;
  title: string;
};

export type MfaPayload = {
  dai?: string;
  txtkn?: string;
  txlnkid?: string;
  c?: string;
  d?: string;
  sh?: string;
  s?: string;
  b?: VersionName;
  os?: VersionName;
  l?: Location;
};

export type VersionName = {
  n?: string;
  v?: string;
};

export type Location = {
  lat?: string;
  lng?: string;
  n?: string;
};

export type NotificationDataIos = {
  aps: Aps;
  mfa: MfaPayload;
};
export type NotificationDataAndroid = MfaPayload;

declare namespace Auth0Guardian {
  export function initialize(auth0Domain: string): Promise<boolean>;

  export function enroll(
    enrollmentURI: string,
    deviceToken: string,
  ): Promise<Enrollment>;

  export function unenroll(enrollmentId: string): Promise<boolean>;

  export function getEnrollments(): Promise<Enrollment[]>;

  export function getTOTP(enrollmentId: string): Promise<string>;

  export function allow(
    notificationData: NotificationDataIos | NotificationDataAndroid,
  ): Promise<boolean>;

  export function reject(
    notificationData: NotificationDataIos | NotificationDataAndroid,
  ): Promise<boolean>;
}

export default Auth0Guardian;
