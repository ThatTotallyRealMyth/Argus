import { useEffect, useState } from "react";

const queryCache = new Map();
const queryInflight = new Map();

function rememberQuery(key, data) {
  const now = Date.now();
  for (const [cachedKey, cached] of queryCache) {
    if (now - cached.time > 5 * 60 * 1000) queryCache.delete(cachedKey);
  }
  queryCache.set(key, { data, time: now });
  while (queryCache.size > 100) queryCache.delete(queryCache.keys().next().value);
}

export function useQuery(key, loader, options = {}) {
  const ttl = options.ttl ?? 30000;
  const [state, setState] = useState(() => {
    const cached = queryCache.get(key);
    return cached && Date.now() - cached.time < ttl ? { key, data: cached.data, loading: false, error: "" } : { key, data: null, loading: true, error: "" };
  });

  useEffect(() => {
    let alive = true;
    const cached = queryCache.get(key);
    if (cached && Date.now() - cached.time < ttl) {
      setState({ key, data: cached.data, loading: false, error: "" });
      return () => { alive = false; };
    }
    setState({ key, data: null, loading: true, error: "" });
    let pending = queryInflight.get(key);
    if (!pending) {
      pending = Promise.resolve().then(loader);
      queryInflight.set(key, pending);
      pending.then(() => queryInflight.delete(key), () => queryInflight.delete(key));
    }
    pending.then((data) => {
      rememberQuery(key, data);
      if (alive) setState({ key, data, loading: false, error: "" });
    }).catch((error) => alive && setState({ key, data: null, loading: false, error: error.message }));
    return () => { alive = false; };
  }, [key, ttl]);

  return selectQueryState(state, key);
}

export function selectQueryState(state, key) {
  if (state.key === key) return { data: state.data, loading: state.loading, error: state.error };
  return { data: null, loading: true, error: "" };
}
