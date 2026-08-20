import pandas as pd
import numpy as np
import json
import logging
from typing import Tuple, Dict, Any, List
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

IDENTIFIER_COLUMNS = [
    'ip', 'src_ip', 'srcip', 'dst_ip', 'dstip', 'sourceip', 'destinationip',
    'source_ip', 'destination_ip', 'source ip', 'destination ip',
    'timestamp', 'time', 'date', 'mac', 'src_mac', 'dst_mac',
    'id', 'record_id', 'index', 'num', 'packet_id', 'seq_num'
]

# Additional keyword substrings to match against column names
IDENTIFIER_KEYWORDS = [
    'source_ip', 'src_ip', 'dest_ip', 'dst_ip', 'destination_ip',
    'timestamp', '_mac', 'mac_', 'address'
]

def inspect_csv(filepath: str) -> Dict[str, Any]:
    """
    Performs initial inspection of the CSV without modification.
    Identifies column names, data types, missing value counts, duplicate rows,
    and suggests the most likely label column.
    """
    df = pd.read_csv(filepath, nrows=50000) # Load up to 50k rows for performance
    
    row_count = len(df)
    col_count = len(df.columns)
    
    # Analyze columns
    columns_list = list(df.columns)
    column_types = {}
    missing_counts = df.isnull().sum().to_dict()
    
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            column_types[col] = "numeric"
        else:
            column_types[col] = "categorical"
            
    # Count duplicate rows
    # We read a larger batch or complete file just for count if possible
    # For initial fast inspection we check the first 50k
    duplicate_count = int(df.duplicated().sum())
    
    # Detect target column
    target_column = None
    target_keywords = ['label', 'class', 'target', 'attack', 'threat', 'category', 'type', 'label_code']
    for col in columns_list:
        if col.lower() in target_keywords:
            target_column = col
            break
            
    if not target_column:
        # If no keyword matches, select the last column
        target_column = columns_list[-1]
        
    # Get class distribution of suggested target column
    class_dist = {}
    if target_column in df.columns:
        class_dist = df[target_column].value_counts().to_dict()
        # Convert keys to string for JSON serialization
        class_dist = {str(k): int(v) for k, v in class_dist.items()}
        
    return {
        "row_count": row_count,
        "col_count": col_count,
        "columns": columns_list,
        "column_types": column_types,
        "missing_counts": {str(k): int(v) for k, v in missing_counts.items()},
        "duplicate_count": duplicate_count,
        "target_column": target_column,
        "class_distribution": class_dist
    }

def preprocess_dataset(
    filepath: str, 
    target_column: str, 
    train_split: float = 0.8
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, Dict[str, Any]]:
    """
    Executes the preprocessing pipeline:
    1. Removes duplicates
    2. Separates target column
    3. Drops obvious identifiers
    4. Handles missing and infinite values
    5. Encodes categorical variables
    6. Returns X_train, X_test, y_train, y_test, and summary metadata.
    """
    df = pd.read_csv(filepath)
    original_row_count = len(df)
    
    # 1. Remove duplicate rows
    df_cleaned = df.drop_duplicates()
    removed_duplicates = original_row_count - len(df_cleaned)
    
    if target_column not in df_cleaned.columns:
        raise ValueError(f"Target column '{target_column}' not found in dataset.")
        
    # Separate features and target
    y = df_cleaned[target_column]
    X = df_cleaned.drop(columns=[target_column])
    
    # 2. Identify and drop obvious identifiers from training features
    dropped_identifiers = []
    cols_to_drop = []
    for col in X.columns:
        if col.lower() in IDENTIFIER_COLUMNS or any(kw in col.lower() for kw in IDENTIFIER_KEYWORDS):
            cols_to_drop.append(col)
            dropped_identifiers.append(col)
            
    X = X.drop(columns=cols_to_drop)
    
    # 3. Handle missing and infinite values
    # Replace inf with nan
    X = X.replace([np.inf, -np.inf], np.nan)
    
    total_missing_handled = int(X.isnull().sum().sum())
    
    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
    
    # Impute missing values
    for col in numeric_cols:
        # Fill missing with median
        median_val = X[col].median()
        if pd.isna(median_val):
            median_val = 0.0
        X[col] = X[col].fillna(median_val)
        
    for col in categorical_cols:
        # Fill missing with mode
        if not X[col].mode().empty:
            mode_val = X[col].mode()[0]
        else:
            mode_val = "Unknown"
        X[col] = X[col].fillna(mode_val)
        
    # 4. Encoding categorical features
    # Let's map categoricals to codes or apply dummy variables
    # For a robust base pipeline, we encode them as labels
    for col in categorical_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        
    # Encode target labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y.astype(str))
    
    classes_list = [str(c) for c in label_encoder.classes_]
    
    # 5. Train/Test split
    # Use stratification to preserve class distributions
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, 
            train_size=train_split, 
            random_state=42, 
            stratify=y_encoded
        )
    except Exception as e:
        logger.warning(f"Stratified split failed: {e}. Falling back to standard split.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, 
            train_size=train_split, 
            random_state=42
        )
        
    summary = {
        "original_records": original_row_count,
        "removed_duplicates": removed_duplicates,
        "missing_values_handled": total_missing_handled,
        "features_used": len(X.columns),
        "feature_names": list(X.columns),
        "target_column": target_column,
        "classes": classes_list,
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "dropped_identifiers": dropped_identifiers
    }
    
    return X_train, X_test, pd.Series(y_train), pd.Series(y_test), summary
