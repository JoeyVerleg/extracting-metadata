#!/bin/bash  
TRACES=$1
OUTPUT=$2
python extract_features.py --traces $TRACES --attack knn --out ../data/features/knn/
python extract_features.py --traces $TRACES --attack kfp --out ../data/features/kfp/
python extract_features.py --traces $TRACES --attack vng++ --out ../data/features/vng/
python extract_features.py --traces $TRACES --attack ll --out ../data/features/ll/
python extract_features.py --traces $TRACES --attack wright --out ../data/features/wright/
python extract_features.py --traces $TRACES --attack CUMUL --out ../data/features/CUMUL/
python extract_features.py --traces $TRACES --attack panchenko --out ../data/features/panchenko/

python classify.py --features ../data/features/knn/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_knn
python classify.py --features ../data/features/kfp/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_kfp
python classify.py --features ../data/features/vng/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_vng
python classify.py --features ../data/features/ll/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_ll
python classify.py --features ../data/features/wright/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_wright
python classify.py --features ../data/features/CUMUL/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_CUMUL
python classify.py --features ../data/features/panchenko/ --train 0.8 --test 0.2 --attack knn --out $OUTPUT_panchenko
