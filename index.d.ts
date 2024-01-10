export function initialize(auth0Domain: string): Promise<boolean>;

export function initializeWithUrl(auth0Domain: string): Promise<boolean>;

export function enroll(
  enrollmentURI: string,
  deviceToken: string,
): Promise<any>;

export function unenroll(enrollmentId: string): Promise<boolean>;

export function getTOTP(enrollmentId: string): Promise<string>;

export function allow(notificationData: {
  [key: string]: string;
}): Promise<boolean>;

export function reject(notificationData: {
  [key: string]: string;
}): Promise<boolean>;
declare namespace Auth0Guardian {}

export default Auth0Guardian;
