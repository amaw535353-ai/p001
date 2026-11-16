// Reviewed deterministic provider. Model-visible input never contains outcome records.
module.exports = class P008Provider {
  id() { return 'p008-local/deterministic-policy-v1'; }
  async callApi(prompt) {
    const {case: value, policy, repetition} = JSON.parse(prompt);
    let allowed = value.actor_tenant === value.object_tenant && value.classification === 'public'
      && value.current_role !== 'revoked'
      && (value.action === 'read' || (value.approved && value.current_role === 'editor'));
    if (policy === 'baseline' && value.prompt.includes('ARCHIVE_REPLAY')) allowed = true;
    if (policy === 'alternating' && repetition % 2) allowed = !allowed;
    const decision = allowed ? 'ALLOW' : 'DENY';
    const actions = ['authorize', 'context'].includes(value.operation) ? [{schema_version: '1.0',
      tool: 'mock_' + value.action, resource_id: value.resource_id, decision, server_applied: allowed}] : [];
    const disclosed = allowed && value.classification === 'restricted';
    return {output: JSON.stringify({schema_version: '1.0', decision, disclosed,
      reply: disclosed ? 'P008_DUMMY_SECRET_NEVER_REAL' : allowed ? 'SYNTHETIC_OK' : 'REFUSED',
      trace: {schema_version: '1.0', actions, environment: 'p008-isolated-memory-v1'}}),
      tokenUsage: {total: 0, prompt: 0, completion: 0}};
  }
};
