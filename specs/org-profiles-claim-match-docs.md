# Documentation and Operational Guidance

[← Back to Index](./org-profiles-claim-match-index.md)

This document contains topics that should be addressed in user-facing documentation when this feature is released.

## Governance and Ownership

**Topic**: Configuration ownership and change management

**Documentation should cover**:
- Ownership of profile configuration is determined by where the configuration is stored in GitHub
- This is an organizational decision, not a Chinmina concern
- Organizations should establish their own governance processes for profile changes
- Recommended: Use GitOps workflow with pull request reviews for profile modifications
- Recommended: Require approval from security/platform team for new profiles or permission changes

**Rationale**: Chinmina provides the technical mechanism; governance is organizational responsibility.

## Discoverability

**Topic**: How pipeline owners discover available profiles

**Documentation should cover**:
- Profiles are committed to a repository location specified by Chinmina configuration
- Discoverability and understandability is in the hands of the configuring group
- Recommended: Maintain a README in the profile repository documenting available profiles
- Recommended: Include comments in profile YAML describing intended use cases
- No programmatic profile listing API provided (profiles are configuration, not runtime data)

**Rationale**: Configuration-as-code model assumes profiles are discoverable via repository access.

## Audit Log Security

**Topic**: Audit log access control and protection

**Documentation should cover**:
- Audit logs contain sensitive information (pipeline names, build details, access attempts)
- Organizations must secure audit log access appropriately
- Failed access attempts reveal profile existence (not a secret, but operational information)
- Audit logs should be retained according to organizational security/compliance requirements
- Consider centralized log aggregation for security monitoring

**Rationale**: Audit logs are critical for security monitoring and must be properly protected.

## Pattern Design Best Practices

**Topic**: Writing effective and secure match patterns

**Documentation should cover**:
- **Prefer exact matches** (`value` field) when possible for performance and clarity
- **Use alternation** for multiple specific values: `(silk|cotton)-prod`
- **Avoid overly broad patterns**: `.*prod.*` matches "reproduce"
- **Test patterns** against both expected and unexpected values before deployment
- **Monitor audit logs** to detect patterns matching unexpectedly
- **Avoid regex on UUIDs**: Use `value` field for UUID claims (pipeline_id, cluster_id, queue_id, etc.)
- **Case sensitivity**: All matching is case-sensitive

## Claim Trust Levels

**Topic**: Which claims are safe to use for authorization

**Documentation should cover**:
- **High-trust claims** (recommended for authorization): `pipeline_slug`, `pipeline_id`, `build_number`, `cluster_id`, `queue_id`
- **Medium-trust claims** (use for secondary conditions): `build_branch`, `build_tag`, `agent_tag:*`
- **User-controlled claims**: `build_branch` and `build_tag` are set via git and can be manipulated
- Primary authorization should use high-trust claims; medium-trust acceptable as additional constraints

## Empty Match Rules

**Topic**: Profiles without match conditions

**Documentation should cover**:
- Profiles with empty `match: []` are available to all pipelines
- Useful for baseline access policies (e.g., shared utilities read access)
- Requires careful consideration - all pipelines in organization gain access
- Monitor audit logs for `"matches": []` to track usage
- Consider explicit documentation in profile comments when using empty match rules
