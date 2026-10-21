"""Vendored old-only RF JSON inference, no sklearn/training/IO at import."""
import math
import struct

def require(ok,message):
    if not ok:raise ValueError(message)

def plain_predict(model,features):
    """Pure standard-library inference; no model fitting or optional imports."""
    require(model['schema']=='OLD_ALI_SIGNED_GAIN_RF_JSON_v1','JSON model schema')
    require(len(features)==model['n_features'],'feature count/order contract')
    x=[]
    for value in features:
        require(type(value) in (int,float) and math.isfinite(value),'finite numeric features required')
        try:rounded=struct.unpack('<f',struct.pack('<f',value))[0]
        except (OverflowError,struct.error):raise ValueError('feature outside float32 range')
        require(math.isfinite(rounded),'feature outside float32 range');x.append(rounded)
    require(model['trees'] and len(model['trees'])==model['n_trees'],'tree census')
    total=0.
    for tree in model['trees']:
        n=len(tree['children_left'])
        require(n and all(len(tree[k])==n for k in ('children_right','feature','threshold','value')),'tree array lengths')
        node=0;visited=0
        while tree['children_left'][node]!=-1:
            visited+=1;require(visited<=n,'tree cycle')
            feature=tree['feature'][node]
            require(type(feature) is int and 0<=feature<len(x),'tree feature index')
            node=tree['children_left'][node] if x[feature]<=tree['threshold'][node] else tree['children_right'][node]
            require(type(node) is int and 0<=node<n,'tree child index')
        require(tree['children_right'][node]==-1 and math.isfinite(tree['value'][node]),'finite regression leaf')
        total+=tree['value'][node]
    return total/len(model['trees'])
