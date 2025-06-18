# Quick start

Via ADBox one can create detectors and use them to detect anomalous behaviors in chosen data. To do so, it is sufficient to compile a [**use-case**](/docs/manual/use_case.md) file summarizing the necessary information and run the following command via the terminal:

```sh
./adbox.sh -u {number}
```

where `{number}` is the number associated with a given use case.

A complete overview of how to define a use case is given in the [use-case definition guide](/docs/manual/use_case.md).

Via a use case one can

- create a detector, by including the `training` settings.
- use a detector for prediction, by including the `prediction` settings.
- both, by including both `training`and `prediction` settings.

Indeed, if the `training`/`prediction` key is present, the ADBox starts the corresponding pipeline in the [anomaly detection engine](/docs/manual/engine.md).

See these examples:

- [Example with notebook integration](/docs/manual/example.md)
- [Detector Dashboard Tutorial](/docs/manual/dashboard_tutorial.md)


