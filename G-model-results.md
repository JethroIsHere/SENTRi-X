# Appendix G — Model results and implementation details

Chapter 4 compares Random Forest, 1D CNN, and equal-weight Hybrid within each test set. The archived zero-shot experiment used a different protocol and must not be treated as a matched baseline for target adaptation. Laboratory counts are unscored.

## Tables G1–G5

### Table G1. Native ToN-IoT holdout (9,962 flows)

| Model | Class | Accuracy | Precision | Recall | F1-Score |
| --- | --- | --- | --- | --- | --- |
| Random Forest | Normal | 97.76% | 0.6077 | 0.9765 | 0.7492 |
| Random Forest | Attack | 97.76% | 0.9992 | 0.9777 | 0.9883 |
| Random Forest | Macro Average | 97.76% | 0.8034 | 0.9771 | 0.8687 |
| 1D CNN | Normal | 95.54% | 0.4325 | 0.9677 | 0.5978 |
| 1D CNN | Attack | 95.54% | 0.9988 | 0.9550 | 0.9764 |
| 1D CNN | Macro Average | 95.54% | 0.7157 | 0.9614 | 0.7871 |
| Hybrid RF-CNN | Normal | 97.66% | 0.5954 | 0.9883 | 0.7431 |
| Hybrid RF-CNN | Attack | 97.66% | 0.9996 | 0.9762 | 0.9877 |
| Hybrid RF-CNN | Macro Average | 97.66% | 0.7975 | 0.9822 | 0.8654 |

[Download table G1 (CSV)](data/G1-model-results.csv)

### Table G2. Archived BoT-IoT zero-shot experiment (144,728 flows; Hybrid only)

| Model | Accuracy | Macro Precision | Macro Recall | Macro F1-Score |
| --- | --- | --- | --- | --- |
| Hybrid Ensemble | 0.0180% | 0.00 | 0.50 | 0.00 |

[Download table G2 (CSV)](data/G2-model-results.csv)

### Table G3. Adapted BoT-IoT holdout (40,000 flows)

| Model | Class | Accuracy | Precision | Recall | F1-Score |
| --- | --- | --- | --- | --- | --- |
| Random Forest | Normal | 99.62% | 0.7167 | 0.9869 | 0.8304 |
| Random Forest | Attack | 99.62% | 0.9999 | 0.9962 | 0.9981 |
| Random Forest | Macro Average | 99.62% | 0.8583 | 0.9916 | 0.9142 |
| 1D CNN | Normal | 99.14% | 0.5249 | 0.9948 | 0.6872 |
| 1D CNN | Attack | 99.14% | 0.9999 | 0.9913 | 0.9956 |
| 1D CNN | Macro Average | 99.14% | 0.7624 | 0.9930 | 0.8414 |
| Hybrid RF-CNN | Normal | 99.55% | 0.6798 | 0.9948 | 0.8077 |
| Hybrid RF-CNN | Attack | 99.55% | 0.9999 | 0.9955 | 0.9977 |
| Hybrid RF-CNN | Macro Average | 99.55% | 0.8399 | 0.9951 | 0.9027 |

[Download table G3 (CSV)](data/G3-model-results.csv)

### Table G4. Adapted CIC-IDS2017 holdout (38,795 flows)

| Model | Class | Accuracy | Precision | Recall | F1-Score |
| --- | --- | --- | --- | --- | --- |
| Random Forest | Normal | 98.89% | 0.9933 | 0.9931 | 0.9932 |
| Random Forest | Attack | 98.89% | 0.9695 | 0.9705 | 0.9700 |
| Random Forest | Macro Average | 98.89% | 0.9814 | 0.9818 | 0.9816 |
| 1D CNN | Normal | 91.86% | 0.9180 | 0.9885 | 0.9519 |
| 1D CNN | Attack | 91.86% | 0.9229 | 0.6101 | 0.7346 |
| 1D CNN | Macro Average | 91.86% | 0.9205 | 0.7993 | 0.8433 |
| Hybrid RF-CNN | Normal | 98.83% | 0.9904 | 0.9954 | 0.9929 |
| Hybrid RF-CNN | Attack | 98.83% | 0.9790 | 0.9573 | 0.9680 |
| Hybrid RF-CNN | Macro Average | 98.83% | 0.9847 | 0.9763 | 0.9804 |

[Download table G4 (CSV)](data/G4-model-results.csv)

### Table G5. Pooled Omni holdout (17,842 flows)

| Model Configuration | Accuracy | Macro Precision | Macro Recall | Macro F1-Score |
| --- | --- | --- | --- | --- |
| Random Forest | 99.42% | 0.9929 | 0.9929 | 0.9929 |
| 1D CNN | 92.70% | 0.8982 | 0.9462 | 0.9160 |
| Hybrid RF-CNN | 97.16% | 0.9553 | 0.9790 | 0.9661 |

[Download table G5 (CSV)](data/G5-model-results.csv)

## Figures G1–G73

Each PDF is bookmarked by figure. Rev4 figure numbers are printed above the original illustrations; some illustrations retain an older embedded caption.

- [Figures G1–G13: Canonical holdout figures](https://github.com/JethroIsHere/SENTRi-X/releases/download/thesis-rev4/G01-G13.pdf)
- [Figures G14–G26: Pooled Omni figures](https://github.com/JethroIsHere/SENTRi-X/releases/download/thesis-rev4/G14-G26.pdf)
- [Figures G27–G46: Laboratory observation figures](https://github.com/JethroIsHere/SENTRi-X/releases/download/thesis-rev4/G27-G46.pdf)
- [Figures G47–G65: Laboratory observation figures](https://github.com/JethroIsHere/SENTRi-X/releases/download/thesis-rev4/G47-G65.pdf)
- [Figures G66–G73: Selected implementation excerpts](https://github.com/JethroIsHere/SENTRi-X/releases/download/thesis-rev4/G66-G73.pdf)

[Key source excerpts at the tested revision](key-excerpts.md)
