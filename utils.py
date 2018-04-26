import ast
import glob
import subprocess
import os
from collections import defaultdict

import pathlib

import shutil


def get_files(path):
    file_list = []

    for f in glob.glob(path + "/**/*", recursive=True):
        if not os.path.isdir(f):
            file_list.append(f)

    return file_list


def get_family(apk):
    return apk.split("/")[-2]


def get_packages(dataset_path):
    packages = dict()
    files = get_files(dataset_path)
    cmd = "/home/pret/Programmi/android-sdk/build-tools/26.0.0/aapt"

    for f in files:
        try:
            res = subprocess.run([cmd, "dump", "badging", f, "| grep package:\ name"], stdout=subprocess.PIPE)
            package = str(res.stdout, encoding="utf-8").split("'")[1]
            packages[f] = package
        except:
            print(f+" probably does not have manifest file. Check it")

    return packages


def count_variants():
    files = get_files("/media/pret/Maxtor1/BENIGN_GOOGLE/Dataset")
    counter = dict()
    for f in files:
        try:
            counter[get_family(f)] += 1
        except:
            counter[get_family(f)] = 1
    print(sorted(counter.items(), key=lambda x: -x[1]))


def read_fn(results_path):
    fn_list = list()
    lines = open(results_path, "r").read().splitlines()
    for l in lines:
        tup = ast.literal_eval(l)
        if tup[1]=="safe":
            fn_list.append(tup[0])
    return fn_list


def get_couple_apks_version(db, test_set):
    cmd = "/home/pret/Programmi/android-sdk/build-tools/26.0.0/aapt"
    files1 = get_files(db)
    files2 = get_files(test_set)
    false_negatives = read_fn("/home/pret/workspace/PycharmProjects/monalizza-v2/benign_all/results.txt")
    good = list()
    for f1 in files1:
        for f2 in files2:
            if get_family(f1) == get_family(f2):
                res = subprocess.run([cmd, "dump", "badging", f1], stdout=subprocess.PIPE)
                v1 = str(res.stdout, encoding="utf-8").split("'")[5]
                res = subprocess.run([cmd, "dump", "badging", f2], stdout=subprocess.PIPE)
                v2 = str(res.stdout, encoding="utf-8").split("'")[5]
                if f2 in false_negatives:
                    print(get_family(f1)+": "+v1+"\t"+v2)
                else:
                    good.append((v1, v2))
    print(good)


def split_by_package():
    move = defaultdict(list)
    pkgs1 = get_packages("/media/pret/Maxtor1/BENIGN_GOOGLE/top-Google-Play")
    pkgs2 = get_packages("/media/pret/Maxtor1/BENIGN_GOOGLE/recon_samples")

    for f, p in pkgs1.items():
        for f2, p2 in pkgs2.items():
            if p == p2:
                move[p].extend([f, f2])
    for p, files in move.items():
        folder = "/media/pret/Maxtor1/BENIGN_GOOGLE/Dataset/" + p
        pathlib.Path(folder).mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copy2(f, folder)


def create_benign_dataset():
    files = get_files("/media/pret/Maxtor1/BENIGN_GOOGLE/Dataset")
    counter = defaultdict(list)
    for f in files:
        counter[get_family(f)].append(f)

    for package, files in counter.items():
        db_folder = "/media/pret/Maxtor1/BENIGN_GOOGLE/Db/"+package
        pathlib.Path(db_folder).mkdir(parents=True, exist_ok=True)
        shutil.move(files[0], db_folder)


def main():
    split_by_package()
    count_variants()
    create_benign_dataset()
    count_variants()

if __name__ == '__main__':
    get_couple_apks_version("/media/pret/Maxtor1/BENIGN_GOOGLE/Dataset/Db",
                            "/media/pret/Maxtor1/BENIGN_GOOGLE/Dataset/Testset")
