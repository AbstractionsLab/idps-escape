| Term               | Definition/Description                                       |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| AD                 | Anomaly detection      |
| CyFORT-Wazuh       | Wazuh deployment as SIEM&XDR subsystem of IDPS-ESCAPE    |
| CyFORT-Suricata    | Suricata deployment as NIDPS subsystem of IDPS-ESCAPE                                       |
| C-CyFORT-Suricata  | Suricata deployment as NIDPS subsystem of IDPS-ESCAPE within the C&C server                   |
| ADBox              | Anomaly Detection subsystem of IDPS-ESCAPE                                                                                            |
| ML                 | Machine learning           |
| MTAD-GAT           | Multivariate Time-series Anomaly Detection via Graph Attention network algorithm                     |
| NID(P)S            | Network Intrusion Detection (and prevention) system                                                                                                               |
| HID(P)S            | Host Intrusion Detection (and Prevention) System               |
| Time-series        | See [Time-series](/docs/manual/time_series.md)           |
| Granularity        | Base time unit. E.g., if the granularity is one minute, we expect a point every minute. |
| Granularity interval| Interval of time whose length is granularity. |
| Unit timestamp     | Initial timestamp of a granularity interval. See [Aggregation and Granularity](/docs/manual/runmodes.md#aggregation-and-granularity). |
| Window             | Subsequence of a time-series of given size. In ADBox, a window contains points at a regular distance (granularity).  |
| Window size        | number of points in a window.    |
| Detection interval |  `detection_interval=(window_size + 1)*granularity`.  |
| Sliding windows' dataset | A dataset containing batch of consecutive windows. |
| Index              | primitive block of an index database      |
| Index date         | For Wazuh indexer the pattern to the index storing the data of a certain date                   |
| Run modes           | Possible modalities to run detection pipeline.  |
| Batch run mode      | Prediction pipeline a processing a batch (of windows) of fixed size (**batch size**), as an almost realtime stream. See [Batch runmode](/docs/manual/runmodes.md#batch-runmode).|
| Batch interval     | The interval of time covered by a batch of (consecutive) windows.  `batch_interval=(window_size + batch_size)*granularity`. |
| Historical run mode | Prediction pipeline processing window between to given timestamps in the past of "arbitrary" size.  See [Historical runmode](/docs/manual/runmodes.md#historical-runmode).  |
| Realtime run mode  | Prediction pipeline a processing a window at the time, as an almost real-time stream.  See [Realtime runmode](/docs/manual/runmodes.md#real-time-runmode).  |
| Online run mode | Either in real time or batch run mode.|
| Offline run mode | Historical run mode |
| Detector | The ensemble of data and functions necessary to perform detection. For MTAD-GAT, this includes for example the trained model and the SPOT objects.  |
| Detector data stream | OpenSearch data stream in Wazuh's indexer associated to a specific detector |