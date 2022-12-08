# -*- coding: utf-8 -*-
"""Anonymization_to_csv.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1elRbhN1aI-ubScFLRQFshkmuRfybVOEg
"""

!unzip /content/drive/MyDrive/ECS235A/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.zip

!pip install yacryptopan
from yacryptopan import CryptoPAn
cp = CryptoPAn(b'32-char-str-for-AES-key-and-pad.')

import pandas as pd
df = pd.read_csv("/content/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

df.head()

import numpy as np

def setToZero(arr, num):
  ind = (num // 8)
  mod = num % 8
  for i in range(0, ind):
    arr[i] = 0
  mod = 32 - mod
  mask = ((1 << mod)-1)
  # print('mask', mask)
  arr[ind] &= mask
  return arr
  
def rev_truncation(src, dest, n):
  new_src = ""
  new_dest = ""
  src_split = src.split(".")
  dest_split = dest.split(".")

  src_split = [int(x) for x in src_split]
  dest_split = [int(x) for x in dest_split]
  src_split = setToZero(src_split, n)
  dest_split = setToZero(dest_split, n)
  
  src_split = [str(x) for x in src_split]
  dest_split = [str(x) for x in dest_split]

  for i in range(4):
    new_src += src_split[i]
    if i != 3:
      new_src += "."

  for i in range(4):
    new_dest += src_split[i]
    if i != 3:
      new_dest += "."

  # new_src = str.encode(new_src)
  # new_dest = str.encode(new_dest)
  return new_src, new_dest

source = df[' Source IP'].to_list()
destination = df[' Destination IP'].to_list()

new_sources = []
new_dests = []
for i in range(len(source)):
  s, d = rev_truncation(source[i],destination[i],20)
  new_sources.append(s)
  new_dests.append(d)

src = df.columns[1]
dest = df.columns[3]

df[src] = new_sources
df[dest] = new_dests

df.head()

def prefanon(L):
  new_ips = []
  for i in L:
    new_ips.append(cp.anonymize(i))
  return new_ips

new_sources = prefanon(source)
new_dests = prefanon(destination)

src = df.columns[1]
dest = df.columns[3]

df[src] = new_sources
df[dest] = new_dests

df.head()

df.to_csv("PrefixPreserved.csv")

df.to_csv("RevTrunc-20.csv")

!cp RevTrunc-20.csv "/content/drive/My Drive/ECS 235 A"

df.columns[0]

df.drop(["Flow ID"],axis=1)

new_sources = [i.replace(".","0") for i in new_sources]

new_dests = [i.replace(".","0") for i in new_dests]

df.head()

new_sources[0]
