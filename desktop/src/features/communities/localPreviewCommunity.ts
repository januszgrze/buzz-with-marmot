/**
 * The named Marmot preview launchers may bypass hosted-community onboarding
 * in development. Normal development, E2E, and release builds stay on the
 * standard onboarding path.
 */
export function shouldAutoConfigureLocalPreviewCommunity(
  isDevelopment: boolean,
  previewFlag: string | undefined,
): boolean {
  return isDevelopment && previewFlag === "1";
}
