import { displayError } from "../../components/displayError";
import { Principal } from "@dfinity/principal";
import { AuthContext } from "./postMessageInterface";

export const sanitizeDerivationOrigin = async (
  authContext: AuthContext
): Promise<AuthContext> => {
  const validationResult = await validateDerivationOrigin(
    authContext.requestOrigin,
    authContext.authRequest.derivationOrigin
  );

  if (validationResult.result === "valid") {
    return authContext;
  }

  await displayError({
    title: "Invalid derivation origin",
    message: `"${authContext.authRequest.derivationOrigin}" is not a valid derivation origin for "${authContext.requestOrigin}"`,
    detail: validationResult.message,
    primaryButton: "Close",
  });

  // notify the client application
  // do this after showing the error because the client application might close the window immediately after receiving the message and might not show the user what's going on
  authContext.postMessageCallback({
    kind: "authorize-client-failure",
    text: `Invalid derivation origin: ${validationResult.message}`,
  });

  // we cannot recover from this, retrying or reloading won't help
  // close the window as it returns the user to the offending application that opened II for authentication
  window.close();

  // return the sanitized authContext anyway in case the browsing context is not script closable
  // (this should never be the case for an authentication flow)
  authContext.authRequest.derivationOrigin = undefined;
  return authContext;
};

export type ValidationResult =
  | { result: "valid" }
  | { result: "invalid"; message: string };

export const validateDerivationOrigin = async (
  authRequestOrigin: string,
  derivationOrigin?: string
): Promise<ValidationResult> => {
  if (
    derivationOrigin === undefined ||
    derivationOrigin === authRequestOrigin
  ) {
    // this is the default behaviour -> no further validation necessary
    return { result: "valid" };
  }

  // check format of derivationOrigin
  const matches = /^https:\/\/([\w-])*(\.raw)?\.ic0\.app$/.exec(
    derivationOrigin
  );
  if (matches === null) {
    return {
      result: "invalid",
      message:
        'derivationOrigin does not match regex "^https:\\/\\/([\\w-])*(\\.raw)?\\.ic0\\.app$"',
    };
  }

  try {
    const canisterId = Principal.fromText(matches[1]); // verifies that a valid canister id was matched TODO: necessary?
    const alternativeOriginsUrl = `https://${canisterId.toText()}.ic0.app/.well-known/ii-alternative-origins`;
    const alternativeOriginsObj = (await fetch(
      // SECURITY CRITICAL: always fetch non-raw
      alternativeOriginsUrl,
      // SECURITY CRITICAL: fail on redirects
      { redirect: "error" }
    ).then((response) => response.json())) as { alternativeOrigins: string[] };

    // check for expected property
    if (!Array.isArray(alternativeOriginsObj?.alternativeOrigins)) {
      return {
        result: "invalid",
        message: `resource ${alternativeOriginsUrl} has invalid format: received ${alternativeOriginsObj}`,
      };
    }

    // check allowed alternative origins
    if (!alternativeOriginsObj.alternativeOrigins.includes(authRequestOrigin)) {
      return {
        result: "invalid",
        message: `"${authRequestOrigin}" is not listed in the list of allowed alternative origins. Allowed alternative origins: ${alternativeOriginsObj.alternativeOrigins}`,
      };
    }
  } catch (e) {
    // return more info
    return {
      result: "invalid",
      message: `An error occurred while validation the derivationOrigin "${derivationOrigin}": ${e.message}`,
    };
  }

  // all checks passed --> valid
  return { result: "valid" };
};
