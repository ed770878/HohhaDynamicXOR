# KPA Inputs

Generating KPA inputs:
```sh
#./genbrut.sh ../hohha <key-jumps> <key-length> <kpa-count>

./genbrut.sh ../hohha 2 128 1000
```

KPA key recovery:
```sh
# from top level dir
./hohha_brut -j2 -l128 -r -f brut/brut-j2-l128-t1000-msg.txt
```

## Notes

Some examples have been provided.

- brut-j2-l128-t500-msg.txt
  - Takes longer than a few hours to solve.
- brut-j2-l128-t1000-msg.txt
  - Takes under an hour to solve (23 minutes)
- brut-j2-l128-t1000-msg-easy.txt
  - Solved in about one minute
- brut-j4-l128-t2000-msg.txt
  - Four jumps! Starting with solution shows it *can* be solved, but...
  - Starting with random takes longer than a few hours to solve.
