import { describe, expect, it } from "vitest";

import { renderAwsCredentials, renderAwsProfile } from "../src/placements/render.js";

const FIELDS = {
  accessKeyId: "AKIAEXAMPLE",
  secretAccessKey: "wJalrEXAMPLEKEY",
  region: "us-east-1",
};

describe("aws.profile renderer", () => {
  it("renders a [profile <name>] block with region", () => {
    expect(renderAwsProfile("prod-deploy", FIELDS)).toBe(
      [
        "[profile prod-deploy]",
        "aws_access_key_id = AKIAEXAMPLE",
        "aws_secret_access_key = wJalrEXAMPLEKEY",
        "region = us-east-1",
      ].join("\n"),
    );
  });

  it("omits the region line when region is absent", () => {
    expect(renderAwsProfile("x", { ...FIELDS, region: null })).toBe(
      ["[profile x]", "aws_access_key_id = AKIAEXAMPLE", "aws_secret_access_key = wJalrEXAMPLEKEY"].join(
        "\n",
      ),
    );
  });

  it("has no leading or trailing newline (the delivery layer adds them)", () => {
    const block = renderAwsProfile("x", FIELDS);
    expect(block.startsWith("\n")).toBe(false);
    expect(block.endsWith("\n")).toBe(false);
  });
});

describe("aws.credentials renderer", () => {
  it("renders a [<name>] block WITHOUT a region line", () => {
    expect(renderAwsCredentials("s3-sync", FIELDS)).toBe(
      [
        "[s3-sync]",
        "aws_access_key_id = AKIAEXAMPLE",
        "aws_secret_access_key = wJalrEXAMPLEKEY",
      ].join("\n"),
    );
  });

  it("uses a bare [name] header (not [profile name])", () => {
    expect(renderAwsCredentials("backups", FIELDS).split("\n")[0]).toBe("[backups]");
  });
});
