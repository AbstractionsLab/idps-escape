# ADBox run modes and time management

A **run mode** is a flag to control the running of the prediction pipeline with respect to the time period of the data analyzed.

Currently, ADBox supports 3 run modes for prediction:
- **HISTORICAL**: running prediction on data from the past.
- **REAL-TIME**: run prediction at regular intervals over new points.
- **BATCH**: almost in real time, we predict anomalies on data gathered in batches. This has a delay which depends on the batch size.


Different run modes are implemented adapting:
- the request time
- and the frequency of the request.

The purpose of this page is to explain the reasoning behind time management within ADBox and the implementation of these run modes.

Notice that the time management operations described below are actually automatically handled as part of the pipelines started from the [AD Engine](/docs/manual/engine.md), according to parameters specified in the [use case](/docs/manual/use_case.md). However, for the sake of clarity, we recall the definition of these parameters and explain the behind-the-scene ideas, using an example throughout. 

## Aggregation and granularity

In time-series anomaly detection, it is often assumed that the input data points are equally distributed in time. This is the case for [MTAD-GAT](/docs/manual/mtad_gat.md) within ADBox.

Therefore, after raw data has been ingested, ADBox aggregates data points according to criteria given as part of the input. See [use-case guide](/docs/manual/use_case.md).

The *aggregation* generates the base points for the subsequent computations. Namely, all the points within a **granularity interval** are used to generate a statistical summary value (e.g. mean, sum, max, ...) of the aggregation interval. 

`granularity` is the base time unit and _every granularity interval is denoted by its initial timestamp_ (**unit timestamp**).

If the time of the request sent to ADBox does not correspond to an exact unit timestamp, all the events up to the request's time are fetched and associated to the antecedent unit timestamp. Unit timestamps computation depends on time unit, for seconds, minutes and hours, the initial point is midnight. For days the units are the first day of the month.

_Attention:_ This implies that events occurring between the request's time and the next unit timestamp may be lost. For this reason, we (plan to) add a delay postponing the request to the next unit timestamp. 

#### Example - part 1


We send a request for ingestion at  `00:03:56.390000` via [data ingestor](/siem_mtad_gat/data_ingestion/) getting the univariate dataset:

```{csv}
timestamp
2024-07-01 00:03:26.083000+00:00    6.0
2024-07-01 00:03:26.126000+00:00    6.0
2024-07-01 00:03:26.126000+00:00    6.0
2024-07-01 00:03:26.232000+00:00    6.0
2024-07-01 00:03:56.130000+00:00    7.0
2024-07-01 00:03:56.178000+00:00    7.0
```

Suppose the granularity is set to `3s`. 

As expected, the fetched timestamps are not spaced at a regular distance, therefore we must aggregate them using [DataAggregator](/docs/manual/data_transformation.md#dataaggregator) of the [Data Transformer](/siem_mtad_gat/data_transformer.py) module. In practice, this operation is part of the *Preprocessing*.

With `sum` as aggregation method we obtain:

```
timestamp
2024-07-01 00:03:24+00:00    24.0
2024-07-01 00:03:27+00:00     0.0
2024-07-01 00:03:30+00:00     0.0
2024-07-01 00:03:33+00:00     0.0
2024-07-01 00:03:36+00:00     0.0
2024-07-01 00:03:39+00:00     0.0
2024-07-01 00:03:42+00:00     0.0
2024-07-01 00:03:45+00:00     0.0
2024-07-01 00:03:48+00:00     0.0
2024-07-01 00:03:51+00:00     0.0
2024-07-01 00:03:54+00:00    14.0
```

![granularity](/docs/manual/_figures/1B3AF_DIA_adbox_granularity.png)

[(cont. to)](#example---part-1)

## Windows

[MTAD-GAT](/docs/manual/mtad_gat.md) decides if a unit timestamp `t` is an anomaly by considering the behavior of a window of designated size (**window size**), ending with time unit corresponding to `t`, i.e., the **detection interval**.

Recall that `t` corresponds to the aggregation of the _subsequent_ events. While the window associated to `t` is composed of `window_size` unit timestamps _preceding_ `t`.

Both [train function](/siem_mtad_gat/mtad_gat_pytorch/train_alab.py) and [prediction function](/siem_mtad_gat/mtad_gat_pytorch/predict_alab.py), given the values in the detection interval, automatically generate a window format consumable by the machine learning model and the [Predictor](/siem_mtad_gat/mtad_gat_pytorch/prediction_alab.py).

#### Example - part 2

[(cont. from)](#example---part-1)

To decide if the fetched timestamps between `[00:03:54,00:03:57)` corresponds to an anomaly, after we have aggregated them, we must feed the window of size `3` ending at `00:03:54`to the prediction function. Namely, we need a window containing, aggregated, the data belonging to a detection interval of `12s`, from `00:03:45` to `00:03:57`.


![window](/docs/manual/_figures/1B3AF_DIA_adbox_window.png)

The window generated by the pipelines looks like the following:

```
timestamp
2024-07-01 00:03:45+00:00    0.0
2024-07-01 00:03:48+00:00    0.0
2024-07-01 00:03:51+00:00    0.0
------
timestamp
2024-07-01 00:03:54+00:00    14.0
```

[(cont. to)](#example---part-3)

### Real-time run mode

Informally, real-time detection should decide if what it happening "now" is an anomaly or not.
In light of the previous explanation, we can formalize this as deciding whether the window associated to the current unit timestamp is marked as an anomaly by the prediction pipeline. 

Therefore, the real time run is implemented in ADBox by 
- fetching the corresponding window of every timestamp unit, 
- running the prediction pipeline over the single window.

The *detector* is the only parameter to be chosen in real-time mode. 

For example, if the granularity is one minute, in real-time we will get a new prediction every minute. With a window size of 3, the prediction for the current minute is obtained by having, as soon as it is finished, the engine fetch the data of the past 4 minutes and run the prediction pipeline with this time frame only.

## Batch mode

In this context a **batch** is a group of windows that are processed together. In fact, to analyze a few consecutive points it is convenient to fetch all data points together, rather than on a window at the time.

ADBox-MTAD-GAT takes as input a [time-series](/docs/manual/time_series.md) $x_1,\dots,x_n$, assuming that the corresponding timestamps $t_0,\dots,t_n$ are spaced at regular distances, i.e. for $i=1,\dots,n$
$$|t_{i}-t_{i-1}| = \texttt{granularity}.$$

As discussed, when presenting the notion of [window](#windows), to decide if $x_k$ (i.e, the aggregation of the events within unit timestamp $t_k$) is an anomaly, the prediction pipeline should fetch and aggregate data to produce $$x_{k-\texttt{window\_size}},\dots,x_k.$$
Similarly, for $t_{k+1}$, we need $x_{k-\texttt{window\_size}+1},\dots,x_{k+1}$. 

Therefore, to evaluate consecutive points, it is sufficient to create a **sliding window** dataset. A sliding window dataset is a **batch** of consecutive windows, which can be generated using fewer points than a generic batch.
Namely, a dataset of size `batch_size` can be generated by using only `batch_size + window_size`
units, instead of `batch_size * window_size`.

The interval of time covered by the batch is called **batch interval**. It may happen that within the desired batch interval there are empty granularity intervals; the substitute value to be used in the ADBox pipelines can also be set as a use-case parameter.

Batches can be used for prediction from different points of view:

- Identify the anomalies between two precise points in time, adopted for [historical runmode](#historical-runmode).
- Predict anomalies for a fixed size set of windows, adopted for [batch run mode](#batch-runmode). 

#### Example - part 3

[(cont. from)](#example---part-2)

We want to get predictions for 8 unit points prior our request at `00:03:56.390000`, rounded at `00:03:57`. Thus, `00:03:33`,`00:03:36`,`00:03:39`,`00:03:41`,`00:03:45`,`00:03:48`,`00:03:51`,`00:03:54`.

Therefore, we have to fetch `batch_size + window_size= 11` unit time stamp, which is a batch interval of 33 seconds.
So, we have to fetch all the data between
`00:03:24` and `00:03:57`.

![batch](/docs/manual/_figures/1B3AF_DIA_adbox_batch.png)

![points](/docs/manual/_figures/1B3AF_DIA_adbox_time_example.png)


### Historical run mode

The historical run mode is designed to apply the detection algorithm between two fixed (past) points in time `start_time` and `end_time`. The aggregation and production of the sliding window dataset follow the principles described above, with the specificity that the first `window_size` unit timestamps do not have a corresponding window, and consequently an anomaly score.

As [already observed](#aggregation-and-granularity), if either `start_time` or `end_time`, or both, are not unit timestamps, data may be lost. 
This can be avoided by flagging as true the rounding above and below for `start_time` and `end_time`, respectively.

![historical](/docs/manual/_figures/1B3AF_DIA_adbox_historical.png)

### Batch run mode

Batch mode is an intermediate approach between real-time and historical. It establishes a trade-off between performance and immediacy.

Informally, batch detection decides whether the last batch of points are anomalous or not.

The *detector* and *batch size* must be specified in the use case, while the batch interval is automatically computed by the engine. When started in batch mode, the engine regularly fetches a batch and runs the prediction pipeline from that moment on.

For example, if the granularity is one minute and the batch size is 5, we will get the prediction of the last 5 minutes all together every 5 minutes.

**Remark:** real-time run mode is batch mode with batch size 1.

## Summary

For every run mode, we summarize the properties and formulas:

- **run mode**: name of the run mode as in a use case.
- **type**: either online or offline. Offline indicates that all the timestamps analyzed are in the past with respect to the request, i.e. availability of the data do not change since request time. Online indicates that once the algorithm is started, it will continuously process new data becoming available.
- **frequency**: frequency of prediction calls, e.g., 1/5min means that a new call is made every five minutes.
- **use-case params**: parameters that must be specified.

As explained in the previous section, time variables are interlaced. For online run modes, they are all directly computed from the timestamp of the request (`request_time`) which is the time when the engine is called. Specifically, if applicable, every request:

- generates a response for every unit timestamp between **start_time_out** (included) and **end_time_out** (excluded),
- fetches data from every unit timestamp between **start_time_fetch** and **end_time_fetch**.

To avoid data loss, a rounding flag can be enabled to round fetching times to a unit timestamp. While output times and online start fetching time are *always* rounded. We denote with a `(<)` or `(>)` next to the value if the rounding is to the prior or the subsequent unit timestamp, respectively.  

Additionally, we recall that
- `detection_interval=(window_size + 1)*granularity`
- `batch_interval=(window_size + batch_size)*granularity`


In the table below `+` and `-` represent shifting to later and before, respectively.

| run mode      | type    | frequency                            | use-case params                                   | start_time_out                           | end_time_out      | start_time_fetch                    | end_time_fetch    |
| ------------ | ------- | ------------------------------------ | ------------------------------------------------- | ---------------------------------------- | ----------------- | ----------------------------------- | ----------------- |
| `historical` | offline | $1$                                  | `detector_id`, `start_time`, `end_time` | `(<)star_time+(window_size*granularity)` | `end_time(>)`     | `(<)star_time`                      | `end_time(>)`     |
| `batch`      | online  | $\frac{1}{\texttt{batch\_interval}}$ | `detector_id`, `batch_size`                 | `end_time_out- batch_size*granularity`   | `request_time(>)` | `end_time_fetch-batch_interval`     | `request_time(>)` |
| `realtime`   | online  | $\frac{1}{\texttt{granularity}}$     | `detector_id`                                   | `end_time_out-granularity`               | `request_time(>)` | `end_time_fetch-detection_interval` | `request_time(>)` |