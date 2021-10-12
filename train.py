import numpy as onp
import jax.numpy as np
from jax import grad, jit, vmap, value_and_grad
from jax import random
from jax.scipy.special import logsumexp
from jax.experimental import optimizers

key = random.PRNGKey(1)

def initialize_morse(key):
    params = []
    raise NotImplementedError
    return params

params = initialize_morse(key)

def forward_pass(params, x):
    y = None
    raise NotImplementedError
    return y

batch_forward = vmap(forward_pass, (None, 0), 0)

def get_center(preds):
    pass

def mean_distance(points, centroid):
    pass

def loss(params, x):
    preds = batch_forward(params, x)
    beta = 0.05

    # centroid of benign points
    cen_b = get_center(preds)

    # centroid of malicious points
    cen_m = get_center(preds)

    # mean distances to centroid in benign cluster
    mean_dis = mean_distance(preds, cen_b)

    # mean distances from benign cluster to malicious cluster centroid
    mean_dis2 = mean_distance(preds, cen_m)

    return mean_dis - beta * mean_dis2

@jit
def update(params, x, opt_state):

    value, grads = value_and_grad(loss)(params, x)

learning_rate = 0.01
opt_init, opt_update, get_params = optimizers.sgd(learning_rate)
opt_state = opt_init(params)

def step(step, opt_state):
  value, grads = value_and_grad(loss)(get_params(opt_state))
  opt_state = opt_update(step, grads, opt_state)
  return value, opt_state

def run_training_loop(num_epochs, opt_state, train_loader):

    train_loss = []

    # get the initial set of parameters
    params = get_params(opt_state)

    for epoch in range(num_epochs):
        for batch_idx, (data, target) in enumerate(train_loader):
            params, opt_state, loss = update(params, data, opt_state)
            train_loss.append(loss)

    return train_loss

