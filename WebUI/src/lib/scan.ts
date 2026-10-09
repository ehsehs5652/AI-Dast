import type { Snapshot } from './events';

export type ExecutionProfileId = 'safe-recon' | 'focused-discovery';

export function scanRetryAction(scan: Pick<Snapshot, 'status' | 'stage'>): 'resume' | 'rescan' | null {
  if (scan.status === 'completed' || scan.status === 'cancelled') return 'rescan';
  if (scan.status !== 'failed') return null;
  return scan.stage === 'Attack' || scan.stage === 'Chaining' || scan.stage === 'Validation'
    ? 'resume'
    : 'rescan';
}

export type ExecutionLimits = {
  readonly requests_per_second: number;
  readonly concurrency: number;
  readonly timeout_seconds: number;
  readonly max_depth: number;
  readonly max_requests: number;
};

export type ScopeExecutionRequirements = {
  readonly scope_max_requests_per_second: number | null;
  readonly required_header: {
    readonly name: 'X-HackerOne' | 'X-Intigriti-Username';
    readonly input_field: 'hackerone_username' | 'intigriti_username';
  } | null;
  readonly operational_constraints: readonly string[];
  readonly profiles: readonly {
    readonly id: ExecutionProfileId;
    readonly limits: ExecutionLimits;
  }[];
};

export class MissingExecutionProfileError extends Error {
  constructor(profile: ExecutionProfileId) {
    super(`Approved Scope does not provide execution profile: ${profile}`);
    this.name = 'MissingExecutionProfileError';
  }
}

export function resolveExecutionLimits(
  requirements: ScopeExecutionRequirements,
  profile: ExecutionProfileId,
): ExecutionLimits {
  const selected = requirements.profiles.find(item => item.id === profile);
  if (!selected) throw new MissingExecutionProfileError(profile);
  return {
    ...selected.limits,
    requests_per_second: Math.min(
      selected.limits.requests_per_second,
      requirements.scope_max_requests_per_second ?? Number.POSITIVE_INFINITY,
    ),
  };
}
