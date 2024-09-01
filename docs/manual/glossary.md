| Term               | Definition/Description                                                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AD                 | Anomaly detection                                                                                                                                                 |
| CyFORT-Wazuh       | Wazuh deployment as SIEM&XDR subsystem of IDPS-ESCAPE                                                                                                             |
| CyFORT-Suricata    | Suricata deployment as NIDPS subsystem of IDPS-ESCAPE                                                                                                             |
| C-CyFORT-Suricata  | Suricata deployment as NIDPS subsystem of IDPS-ESCAPE within the C&C server                                                                                       |
| ADBox              | Anomaly Detection subsystem of IDPS-ESCAPE                                                                                                                        |
| ML                 | Machine learning                                                                                                                                                  |
| MTAD-GAT           | Multivariate Time-series Anomaly Detection via Graph Attention network algorithm                                                                                  |
| NID(P)S            | Network Intrusion Detection (and prevention) system                                                                                                               |
| HID(P)S            | Host Intrusion Detection (and Prevention) System                                                                                                                  |
| Time-series        | See [[Time-series]]                                                                                                                                               |
| Granularity        | Base time unit. E.g., if the granularity is one minute, we expect a point every minute. |
| Window             | Subsequece of a time-series of given size. In ADBox, a window contains points at a regular distance (granularity).                                                |
| Window size        | number of points in a window.                                                                                                                                     |
| Detection interval | granularity times window size                                                                                                                                     |
| index              | primitive block of an index database                                                                                                                              |
| index date         | For Wazuh indexer the pattern to the index storing the data of a certain date                                                                                     |
| runmodes           | Possible modalities to run detection pipeline.                                                                                                                    |
| batch runmode      | Prediction pipeline a processing a batch (of windows) of fixed size (**batch size**), as an almost realtime stream                                                |
| realtime run mode  | Prediction pipeline a processing a window at the time, as an almost realtime stream                                                                               |
| historical runmode | Prediction pipeline processing window between to given timestamps in the past of "arbitrary" size.                                                                |
| batch interval     | batch size * granularity                                                                                                                                          |