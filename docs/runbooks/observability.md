# Controller observability

`GET /api/v1/metrics` returns Prometheus text format 0.0.4. It uses the same session authentication and viewer permission as other read API routes. A scraper must present a valid session cookie through the existing authentication boundary. Development authentication modes also expose this endpoint without authentication and are intended only for isolated environments. Responses set `Cache-Control: no-store`.

| Metric | Meaning | Labels |
| --- | --- | --- |
| `egressdeck_controller_http_requests_total` | Completed requests reaching the controller API handler. Protected requests enter this handler after authentication and authorization; rejected authentication, SPA assets, and login routes are excluded. Health checks and metrics requests are included. Counters reset on controller restart. | `method`, `route`, `status_class` |
| `egressdeck_controller_http_request_duration_seconds` | Duration histogram for the same completed requests, with bounds 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, and 10 seconds plus infinity. | `method`, `route`, `status_class` |
| `egressdeck_controller_operations` | Count of retained local operation journal records in each lifecycle state at scrape time. An applied record does not prove current gateway or firewall state. | `state` |
| `egressdeck_controller_operation_snapshot_success` | `1` when the local operation journal snapshot succeeded; `0` when it failed. Operation gauges are omitted on failure to avoid publishing false zero counts. | None |

Routes are registered templates such as `/api/v1/providers/{id}`. Unknown routes use `unmatched`; unsupported HTTP methods use `OTHER`. Statuses use classes such as `2xx` and `5xx`. No request URL, object ID, username, address, domain, query, header, or error message becomes a metric label. Operation states come from a fixed list; unrecognized states aggregate into `other`.

Scrapes read local controller records and do not query remote engines or firewalls. Journal reads receive a two second context deadline. No connection, packet, bandwidth, or proxy/direct traffic metrics are advertised by this endpoint. Use the operation and gateway readback API for the latest available observed and verified evidence; packet-path qualification remains a separate lab gate.

Example query for the controller API error rate:

```promql
sum(rate(egressdeck_controller_http_requests_total{status_class="5xx"}[5m]))
/
sum(rate(egressdeck_controller_http_requests_total[5m]))
```

Example query for API latency by route:

```promql
histogram_quantile(0.95,
  sum by (le, route) (rate(egressdeck_controller_http_request_duration_seconds_bucket[5m]))
)
```

Check `egressdeck_controller_operation_snapshot_success` alongside operation state gauges. A missing gauge or an unavailable scrape is not evidence of zero failed or unknown operations.
