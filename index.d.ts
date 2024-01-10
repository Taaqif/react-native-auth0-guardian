export type Enrollment = {
  id: string;
  userId: string;
  period: number;
  digits: number;
  algorithm: string;
  secret: string;
  deviceIdentifier: string;
  deviceName: string;
  deviceGCMToken: string;
  deviceToken: string;
  privateKey: string;
};
export function initialize(auth0Domain: string): Promise<boolean>;

export function enroll(
  enrollmentURI: string,
  deviceToken: string,
): Promise<Enrollment>;

export function unenroll(enrollmentId: string): Promise<boolean>;

export function getEnrollments(): Promise<Enrollment[]>;

export function getTOTP(enrollmentId: string): Promise<string>;

export function allow(notificationData: {
  [key: string]: string;
}): Promise<boolean>;

export function reject(notificationData: {
  [key: string]: string;
}): Promise<boolean>;
declare namespace Auth0Guardian {}

export default Auth0Guardian;
