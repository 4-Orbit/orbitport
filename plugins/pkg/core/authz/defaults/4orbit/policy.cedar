// 4Orbit demo organization, ported from 4orbit prototype-1/policies/policy.cedar.
//
// Developers may encrypt with demo-key until it expires and with dev-key.
// Security agents may rotate every demo key. Deployment agents may encrypt
// with prod-key. Everything else is denied by default.
//
// `use` in Prototype 1 meant exactly `encrypt` (D-013), so these grants name
// kms.Encrypt. Write `action in Action::"use"` to grant the whole use group.

// Time-limited (US5): context.currentTime is trusted plugin time in Unix
// epoch seconds. The grant holds while currentTime < 1800000000
// (2027-01-15T08:00:00Z) and is denied at and after that instant.
@id("developer-encrypt-demo-key")
permit (
  principal in Role::"developer",
  action == Action::"kms.Encrypt",
  resource == Key::"demo-key"
)
when { context.currentTime < 1800000000 };

@id("security-rotate-demo-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"demo-key"
);

@id("developer-encrypt-dev-key")
permit (
  principal in Role::"developer",
  action == Action::"kms.Encrypt",
  resource == Key::"dev-key"
);

@id("security-rotate-dev-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"dev-key"
);

@id("security-rotate-prod-key")
permit (
  principal in Role::"security",
  action == Action::"kms.RotateKey",
  resource == Key::"prod-key"
);

@id("deployment-encrypt-prod-key")
permit (
  principal in Role::"deployment",
  action == Action::"kms.Encrypt",
  resource == Key::"prod-key"
);
