import { Principal } from "@dfinity/principal";

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
    console.log("derivationOrigin validation: equal or undefined");
    return { result: "valid" };
  }

  // check format of derivationOrigin
  const matches = /^https:\/\/([\w-])*(\.raw)?\.ic0\.app$/.exec(
    derivationOrigin
  );
  if (matches === null) {
    console.log("derivationOrigin validation: invalid, no match");
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
      console.log("derivationOrigin validation: invalid, wrong format");
      return {
        result: "invalid",
        message: `resource ${alternativeOriginsUrl} has invalid format: received ${alternativeOriginsObj}`,
      };
    }

    // check allowed alternative origins
    if (!alternativeOriginsObj.alternativeOrigins.includes(authRequestOrigin)) {
      console.log("derivationOrigin validation: invalid, not whitelisted");

      return {
        result: "invalid",
        message: `"${authRequestOrigin}" is not listed in the list of allowed alternative origins. Allowed alternative origins: ${alternativeOriginsObj.alternativeOrigins}`,
      };
    }
  } catch (e) {
    console.log("derivationOrigin validation: invalid, exception " + e.message);
    // return more info
    return {
      result: "invalid",
      message: `An error occurred while validation the derivationOrigin "${derivationOrigin}": ${e.message}`,
    };
  }

  // all checks passed --> valid
  console.log("derivationOrigin validation: valid, checks passed");
  return { result: "valid" };
};
