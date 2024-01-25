import pandas as pd
import catboost
import joblib


def process_csv(file_path, model_path):
    df = pd.read_csv(file_path)
    df = df.drop(['Project', 'Race', 'Primary_Diagnosis', 'Case_ID'], axis=1)
    df = df.drop(df[df['Gender'] == '--'].index)
    df = df.drop(df[df['Age_at_diagnosis'] == '--'].index)
    df['Age_at_diagnosis'] = df['Age_at_diagnosis'].str.split().str[0].astype(int)
    columns_to_replace = ['IDH1', 'TP53', 'ATRX', 'PTEN', 'EGFR', 'CIC', 'MUC16', 'PIK3CA', 'NF1', 'PIK3R1',
                          'FUBP1', 'RB1', 'NOTCH1', 'BCOR', 'CSMD3', 'SMARCA4', 'GRIN2A', 'IDH2', 'FAT4', 'PDGFRA']
    df[columns_to_replace] = df[columns_to_replace].replace({'MUTATED': 1, 'NOT_MUTATED': 0}).astype(int)
    df["Gender"] = df["Gender"].replace({'Male': 1, 'Female': 0}).astype(int)
    bins = [18, 35, 50, 65, float('inf')]
    labels = ['19-35', '36-50', '51-65', '66+']
    df['Age_at_diagnosis'] = pd.cut(df['Age_at_diagnosis'], bins=bins, labels=labels, right=False)
    df.rename(columns={'Age_at_diagnosis': 'Age_group'}, inplace=True)
    df = pd.get_dummies(df, columns=['Age_group'], prefix='Age_group')
    columns = df.columns.tolist()
    new_order = columns[:1] + columns[-4:] + columns[1:-4]
    df = df[new_order]

    columns_to_convert = ['Age_group_19-35', 'Age_group_36-50', 'Age_group_51-65', 'Age_group_66+']
    df[columns_to_convert] = df[columns_to_convert].astype(int)

    loaded_model = joblib.load(model_path)
    predictions = loaded_model.predict(df)
    if predictions.ndim > 1:
      # Преобразование в одномерный массив
      predictions = predictions.flatten()

    return predictions