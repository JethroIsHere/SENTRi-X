"""Model training routines for Random Forest and CNN architectures.

All training functions:
* Train strictly on train split (no test data leakage).
* Require explicit validation data for CNN (no automatic validation_split
  on resampled data).
* Use deterministic seeds.
* Standardize on binary classification with Attack as class 1.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from sentrix_ml.schema import NUM_FEATURES, EXPECTED_FEATURES


def build_cnn_model(input_shape: tuple[int, int] = (NUM_FEATURES, 1)):
    """Build the canonical SENTRi-X 1D-CNN model architecture."""
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout

    model = Sequential([
        Conv1D(filters=64, kernel_size=3, activation="relu", input_shape=input_shape),
        MaxPooling1D(pool_size=2),
        Conv1D(filters=128, kernel_size=3, activation="relu"),
        MaxPooling1D(pool_size=2),
        Flatten(),
        Dense(128, activation="relu"),
        Dropout(0.5),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


def train_rf(
    X_train: np.ndarray | pd.DataFrame,
    y_train: np.ndarray | pd.Series,
    *,
    n_estimators: int = 100,
    max_depth: Optional[int] = None,
    random_state: int = 42,
    n_jobs: int = -1,
) -> RandomForestClassifier:
    """Train a Random Forest classifier on training data only."""
    if isinstance(X_train, pd.DataFrame):
        X_train = X_train.to_numpy(dtype=float)
    if isinstance(y_train, pd.Series):
        y_train = y_train.to_numpy(dtype=int)

    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        n_jobs=n_jobs,
    )
    rf.fit(X_train, y_train)
    return rf


def train_cnn(
    X_train: np.ndarray | pd.DataFrame,
    y_train: np.ndarray | pd.Series,
    X_val: np.ndarray | pd.DataFrame,
    y_val: np.ndarray | pd.Series,
    *,
    epochs: int = 10,
    batch_size: int = 256,
    verbose: int = 1,
    callbacks: list[Any] | None = None,
):
    """Train the CNN model with separate validation data (no synthetic leakage)."""
    if isinstance(X_train, pd.DataFrame):
        X_train = X_train.to_numpy(dtype=float)
    if isinstance(y_train, pd.Series):
        y_train = y_train.to_numpy(dtype=int)
    if isinstance(X_val, pd.DataFrame):
        X_val = X_val.to_numpy(dtype=float)
    if isinstance(y_val, pd.Series):
        y_val = y_val.to_numpy(dtype=int)

    X_train_3d = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_val_3d = X_val.reshape(X_val.shape[0], X_val.shape[1], 1)

    model = build_cnn_model(input_shape=(X_train.shape[1], 1))
    history = model.fit(
        X_train_3d,
        y_train,
        validation_data=(X_val_3d, y_val),
        epochs=epochs,
        batch_size=batch_size,
        verbose=verbose,
        callbacks=callbacks or [],
    )
    return model, history
