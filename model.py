#!/usr/bin/env python
# coding: utf-8

# In[38]:


import pandas as pd
import numpy as np
NORM_LEN = 6000
DDOS_LEN = 4000
data1 = pd.read_csv("norm.csv")
data2 = pd.read_csv("ddos.csv")
data1 = data1.sample(NORM_LEN)
data2 = data2.sample(DDOS_LEN)
data = pd.concat([data1, data2], ignore_index=True, sort=False)
shuffle = data.sample(frac=1, random_state=101).reset_index()
shuffle.head()


# In[39]:


shuffle.fillna(0, inplace=True)
df = shuffle


# In[40]:


pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)


# In[41]:


test_df = df.copy()


# In[42]:


test_df.replace([np.inf, -np.inf], np.nan, inplace=True)
test_df.dropna(how="all", inplace=True)

number_inf = test_df[test_df == np.inf].count()


# In[43]:


def ip2int(ip):
    ip_list = list(map(int, ip.split('.')))
    num = 0
    for i in ip_list:
        num *= 256
        num += i
    return num


# In[44]:


def delete_first_zero(val):
    if val[0] == '0':
        return val[1:]
    return val

def time2int(tm):
    tm_split = tm.split(' ')
    day_info = tm_split[0].split('/')
    day_info = list(map(delete_first_zero, day_info))
    day_info = list(map(int, day_info))
    day_amount = day_info[0] + (day_info[1] - 1) * 30 + (day_info[2] - 1970) * 365
    
    time_info = tm_split[1].split(':')
    time_info = list(map(delete_first_zero, time_info))
    time_info = list(map(int, time_info))
    sec_amount = 60 * (time_info[0] * 60 + time_info[1]) + time_info[2]
    
    if len(tm_split) == 3 and tm_split[-1] == 'PM':
        sec_amount += 3600 * 12
    sec_amount += day_amount * 24 * 3600
    
    return sec_amount


# In[45]:


y = test_df['Label']
test_df = test_df.drop(['Label'], axis=1)
test_df['Src IP'] = test_df['Src IP'].apply(ip2int)
test_df['Dst IP'] = test_df['Dst IP'].apply(ip2int)
test_df['Timestamp'] = test_df['Timestamp'].apply(time2int)
test_df.head()


# In[46]:


IMPORTANT_COLS = ['Src IP',
                  'Dst IP',
                  'Timestamp',
                  'Src Port',
                  'Dst Port',
                  'Protocol','Flow Duration',
                  'Flow Byts/s',
                  'Flow Pkts/s',
                  'Pkt Len Var',
                  'Down/Up Ratio'
                 ]


# In[47]:


test_df = test_df.drop([i for i in list(test_df.columns) if i not in IMPORTANT_COLS], axis=1)
test_df.head()


# In[48]:


test_df = test_df.fillna(0)


# In[49]:




test_df = test_df.astype(np.int64)


# In[50]:


df_z_scaled = test_df.copy()
  
# apply normalization techniques
for column in df_z_scaled.columns:
    df_z_scaled[column] = (df_z_scaled[column] -
                           df_z_scaled[column].mean()) / df_z_scaled[column].std()
df_z_scaled = df_z_scaled.fillna(0)
df_z_scaled.head()


# In[51]:


y = y.str.replace('ddos', '1').str.replace('Benign','0')
y = y.astype(np.int64)


# In[52]:


from sklearn.model_selection import train_test_split

X_train, X_val, Y_train, Y_val = train_test_split(df_z_scaled, y, test_size=0.3, random_state=42)


# In[53]:


X_train.head()


# In[54]:


hyperparamters = {
    "learning_rate": [0.1,0.01,0.001],
    "batch_size": [1024,2048],
    "kernels": [1,2,4,8,16,32,64],
    "regularization" : ['l1','l2'],
    "dropout" : [0.5,0.7,0.9]
}


# In[87]:


from tensorflow.keras.optimizers import Adam,SGD
from tensorflow.keras.layers import Input, Dense, Activation, Flatten, Conv2D
from tensorflow.keras.layers import Dropout, GlobalMaxPooling2D
from tensorflow.keras.models import Model, Sequential, load_model, save_model
from sklearn.metrics import f1_score, accuracy_score, confusion_matrix
from sklearn.utils import shuffle
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV

def Conv2DModel(model_name,input_shape,kernel_col, kernels=64,kernel_rows=3,learning_rate=0.01,regularization=None,dropout=None):
    model = Sequential(name=model_name)
    regularizer = regularization

    model.add(Conv2D(kernels, (kernel_rows,kernel_col), strides=(1, 1), input_shape=input_shape, kernel_regularizer=regularizer, name='conv0'))
    if dropout != None and type(dropout) == float:
        model.add(Dropout(dropout))
    model.add(Activation('relu'))

    model.add(GlobalMaxPooling2D())
    model.add(Flatten())
    model.add(Dense(1, activation='sigmoid', name='fc1'))

    print(model.summary())
    compileModel(model, learning_rate)
    return model

def compileModel(model,lr):
    # optimizer = SGD(learning_rate=lr, momentum=0.0, decay=0.0, nesterov=False)
    optimizer = Adam(learning_rate=lr, beta_1=0.9, beta_2=0.999, epsilon=None, decay=0.0, amsgrad=False)
    model.compile(loss='binary_crossentropy', optimizer=optimizer,metrics=['accuracy'])  # here we specify the loss function


seed = 101
np.random.seed(seed)

model_name="DEFENDERv1.2"
keras_classifier = KerasClassifier(build_fn=Conv2DModel,model_name=model_name, input_shape=(None, X_train.shape[0],X_train.shape[1]),kernel_col=X_train.shape[1])
kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=seed)
rnd_search_cv = GridSearchCV(keras_classifier, hyperparamters, cv=kfold, refit=True, return_train_score=True)


# In[88]:


rnd_search_cv.fit(X_train, Y_train, epochs=1, validation_data=(X_val, Y_val))
print("Best parameters: ", rnd_search_cv.best_params_)


# In[80]:


best_model = rnd_search_cv.best_estimator_.model
Y_pred_val = (best_model.predict(X_val) > 0.5)
Y_true_val = Y_val.reshape((Y_val.shape[0], 1))
f1_score_val = f1_score(Y_true_val, Y_pred_val)
accuracy = accuracy_score(Y_true_val, Y_pred_val)


# In[ ]:




