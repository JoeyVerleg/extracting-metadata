#!/bin/bash  
TRACES=$1
OUTPUT=$2
python extract_features.py --traces $TRACES --attack knn --out ../$OUTPUT/features/knn/
python extract_features.py --traces $TRACES --attack kfp --out ../$OUTPUT/features/kfp/
python extract_features.py --traces $TRACES --attack vng++ --out ../$OUTPUT/features/vng/
python extract_features.py --traces $TRACES --attack ll --out ../$OUTPUT/features/ll/
python extract_features.py --traces $TRACES --attack wright --out ../$OUTPUT/features/wright/
python extract_features.py --traces $TRACES --attack CUMUL --out ../$OUTPUT/features/CUMUL/
python extract_features.py --traces $TRACES --attack panchenko --out ../$OUTPUT/features/panchenko/

python classify.py --features ../$OUTPUT/features/knn/ --train 0.8 --test 0.2 --attack knn --out ../$OUTPUT/knn-result
python classify.py --features ../$OUTPUT/features/kfp/ --train 0.8 --test 0.2 --attack kfp --out ../$OUTPUT/kfp-result
python classify.py --features ../$OUTPUT/features/vng/ --train 0.8 --test 0.2 --attack vng++ --out ../$OUTPUT/vng-result
python classify.py --features ../$OUTPUT/features/ll/ --train 0.8 --test 0.2 --attack ll --out ../$OUTPUT/ll-result
python classify.py --features ../$OUTPUT/features/wright/ --train 0.8 --test 0.2 --attack wright --out ../$OUTPUT/wright-result
python classify.py --features ../$OUTPUT/features/CUMUL/ --train 0.8 --test 0.2 --attack CUMUL --out ../$OUTPUT/CUMUL-result
python classify.py --features ../$OUTPUT/features/panchenko/ --train 0.8 --test 0.2 --attack panchenko --out ../$OUTPUT/panchenko-result
