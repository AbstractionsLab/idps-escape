# Time-series

A **univariate time-series** is a sequence of real values 
$$
\overrightarrow{x}=(x_1,..,x_n )\in{R}^n
$$ 
Similarly, a **multivariate time-series** is a sequence of real vectors  
$$
\overrightarrow{X} = (\overrightarrow{x}_1,..,\overrightarrow{x}_n ) \in \mathbb{R}^{n \times k}
$$ 
where $n$ is the maximum length of timestamps, and $k$ is the number of features in the input.
A time-series anomaly detection algorithm that takes as input either $\overrightarrow{x}$ or $\overrightarrow{X}$ and outputs $y\in \left\{0,1\right\}^n$ such that $y_i=1$ if the $i^{th}$ timestamp is an anomaly.

$$
\overrightarrow{X} = (\overrightarrow{x}_1,\dots,\overrightarrow{x}_{n})=
\overset{ timestamps }{\begin{bmatrix}
{x}_{1,1} &\dots&{x}_{1,n}\\
\vdots & \ddots & \vdots\\
{x}_{k,1} &\dots&{x}_{k,n}
\end{bmatrix}} { features}
$$

