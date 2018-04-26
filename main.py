import json
import os
import time

import pathlib

from compute_jaccard import compute_jaccard
from detection import detection_mlw
from digest_extraction2 import initialize_database, generate_fuzzy_hashes, print_readable_json
from stats import mlw_stats


def run_detection(data_folder, test_samples=None):
    pathlib.Path(data_folder).mkdir(parents=True, exist_ok=True)
    test_hashes_file_avail = os.path.exists(data_folder + "/hashes.txt")

    if test_hashes_file_avail:
        db_hashes = read_hashes_file("hashes_database.txt")
        test_hashes = read_hashes_file(data_folder + "/hashes.txt")
        detections = compute_jaccard(db_hashes, test_hashes, data_folder + "/jaccard_scores.txt")
    else:
        db_hashes = read_hashes_file("hashes_database.txt")
        start = time.time()
        test_hashes = generate_fuzzy_hashes(test_samples, data_folder)
        print("Testset fuzzy generation: " + str(time.time() - start))
        start = time.time()
        detections = compute_jaccard(db_hashes, test_hashes, data_folder + "/jaccard_scores.txt")
        print("Jaccard comparison: " + str(time.time() - start))

    detection_mlw(detections, data_folder)
    mlw_stats(data_folder + "/classifications.txt")


def generate_digests():
    return initialize_database(database, data_folder), generate_fuzzy_hashes(testset, data_folder)


def read_digests():
    return json.loads(open(data_folder+"/hashes_database.json", "r").read()), \
           json.loads(open(data_folder+"/hashes_testset.json", "r").read())


if __name__ == '__main__':
    database = "/home/pret/Uni/Tesi/Datasets/Reliable/mlw_40/db"  # database path
    testset = "/home/pret/Uni/Tesi/Datasets/Reliable/mlw_40/test_mlw"  # test set path
    data_folder = "all_reliable_mlw2"

    start = time.time()
    db_json, test_json = generate_digests()
    #db_json, test_json = read_digests()
    print("Digests generation: " + str(time.time() - start))
    detections = compute_jaccard(db_json, test_json, data_folder+"/jaccard_scores.json")
    print("Ended Jaccard computation after: " + str(time.time() - start))
    detection_mlw(detections, data_folder+"/results.txt")
    print("Total time: " + str(time.time() - start))
    mlw_stats(data_folder+"/results.txt")
