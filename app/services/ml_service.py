import pandas as pd
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def train_model():
    data = []

    for _ in range(200):
        data.append([random.randint(1,5), 0])

    for _ in range(200):
        data.append([random.randint(6,15), 1])

    df = pd.DataFrame(data, columns=["activity_count", "attack"])

    X = df[["activity_count"]]
    y = df["attack"]

    X_train, X_test, y_train, y_test = train_test_split(X, y)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    return model
