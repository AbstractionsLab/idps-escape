## MTAD-GAT: Multivariate Time-series Anomaly Detection via Graph Attention Network

MTAD-GAT (Multivariate Time-series Anomaly Detection via Graph Attention Network) is a self-supervised learning framework for anomaly detection in multivariate time-series ([Zhao2020](https://arxiv.org/abs/2009.02040)).

The strengths of MTAD-GAT are as follows:

- A joint consideration of temporal and spatial dependencies. Each component 
of the multivariate vectors represents an individual feature. In this sense, 
a multivariate time-series encodes the synchronization of multiple time-series 
evolution in time. To capture the causal relationships between multiple features 
MTAD-GAT uses a feature-oriented graph attention layer. Simultaneously, a 
time-oriented graph attention layer captures the dependencies along the temporal 
dimension. This information is then fused via a GRU layer. 

- A joint optimization of a forecasting-based model and a reconstruction-based 
model. A forecasting-based model detects anomalies based on prediction errors, 
while a reconstruction-based model learns the representation for the entire 
time-series by reconstructing the original input based on some latent variables ([Zhao2020](https://arxiv.org/abs/2009.02040)).. The MTAD-GAT training process updates the parameters from two instances of both models simultaneously. Namely, the loss function is defined as the sum of 
two optimization targets.

More precisely, the model consists of: 

1. Preprocessed multivariate time-series are fed to a 1-D convolution at the first layer to extract high-level features from each time-series input.

2. The output is fed to two parallel graph attention (GAT) layers. 

3. The concatenation of the output representations from the 1-D convolution layer and two GAT layers, is fed into a Gated Recurrent Unit (GRU) layer with d1 hidden dimensions. 

4. The GRU layer’s output is fed into a forecasting-based model and a reconstruction-based model in parallel to obtain the final result.

In the original paper is describes an implementation of the layers and of the joint optimization strategy. However, we can consider MTAD-GAT more as a paradigm rather than a single algorithm. In fact, the various components and models can be adapted to specific applications. For example, the reconstruction models can be implemented as a VAE as in the original paper, but also using a different family of ML algorithms.

For ADBox we adapted the implementation [ML4ITS/mtad-gat-pytorch](https://github.com/ML4ITS/mtad-gat-pytorch).


## Assumptions and terminology

A multivariate time-series is a sequence of $n$ vectors of dimensions $k$. See [Time-series](./time_series.md). 
In this context:

- $n$ is the **window size**, which is the number of **timestamps**.

- $k$ is the number of **features**.

- We assume the timestamps to be at a regular distance e.g., every minute, every 30s, every 2 hours. This distance is called **granularity**.

- The **detection interval** is the time length of a window $detection\_interval \coloneqq granularity \cdot window\_size$.

- We identify a window with its initial timestamp.

Given a predefined window size, the algorithm expects as input a set of points (of dimension $k$) with a certain granularity. In practice, this is a dataframe with $k$ columns, indexed with regular timestamps. 


For example, the input can be a measure of two quantities $A$ and $B$ every minute from 3PM to 5PM. In this case the input has 120 timestamps with 2 features. 

The input can be used to train a **detector** or as input for obtaining a prediction from an already trained detector. 

More precisely, the algorithm automatically extracts the **sliding windows** for this dataset. Namely, if the window size is 10, so the detection interval is 10 minutes, the algorithm will create a dataset of windows to feed to the train/prediction function. In other words, a window is a base unit multivariate time-series on which the actions are performed.
A single window is an acceptable input.

For every window the algorithm computes its **anomaly score**, which is an real number, and if this is above a certain **threshold**, the window is labelled as **anomaly**. The threshold is determined dynamically by using the Peak-over-Threshold (POT) method.

In conclusion, _a timestamp is flagged as an **anomaly** the behavior of the following detection interval is anomalous_, according to the above procedure.


