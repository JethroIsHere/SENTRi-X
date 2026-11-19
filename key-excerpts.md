# Key implementation excerpts

These links open only the selected defensive implementation sections at the tested commit cited in reference 59. The public lab review rule is summarized below.

1. [Sensor delivery and acknowledgement](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/edge/sentrix_sensor.py#L520-L532)
2. [Training-only scaling and balancing](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/sentrix_ml/train_source.py#L111-L117)
3. [Random Forest fitting](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/sentrix_ml/training.py#L58-L65)
4. [One-dimensional CNN architecture](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/sentrix_ml/training.py#L29-L40)
5. [Equal-weight Hybrid fusion](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/sentrix_ml/inference.py#L106-L114)
6. [Live-flow ingestion](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/backend/main.py#L1063-L1073)
7. [Operational alert gate](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/backend/main.py#L708-L720)
8. [Per-flow RF SHAP calculation](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/backend/main.py#L356-L363)
9. [RF-oriented LIME output](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/backend/main.py#L416-L428)
10. [Live dashboard rate calculation](https://github.com/JethroIsHere/SENTRi-X/blob/55f4def5c1a715b47f550d5a256dc0058774280e/frontend/src/context/SystemContext.tsx#L26-L33)
11. **Trial validity:** Candidate events remain unscored until independent review establishes trial validity and matches an alarm to the event. See [Appendix D](D-lab-observations.md).
