// Synthetic local policy provider. No network clients, keys, dynamic modules or eval.
module.exports = class P007Provider {
  id() { return 'p007-local-policy-v1'; }
  async callApi(prompt) {
    const {case: input, policy} = JSON.parse(prompt);
    let result;
    if (input.action === 'read') {
      const allowed = input.actor_tenant === input.object_tenant || !policy.isolation;
      result = {http_status: allowed ? 200 : 403, decision: allowed ? 'ALLOW' : 'DENY'};
    } else if (input.action === 'model') {
      const allowed = input.model === 'synthetic-public';
      result = {decision: allowed ? 'ALLOW' : 'DENY', downstream_calls: Number(allowed)};
    } else if (input.action === 'prompt') {
      const denied = ['ignore previous', 'reveal hidden', 'untrusted instruction'].some(x => input.input.toLowerCase().includes(x));
      result = {decision: denied ? 'DENY' : 'ALLOW', disclosure: false, output: denied ? 'REFUSED' : 'SYNTHETIC_OK'};
    } else {
      return {error: 'Unsupported synthetic action'};
    }
    return {output: JSON.stringify(result), tokenUsage: {total: 0, prompt: 0, completion: 0}};
  }
};
