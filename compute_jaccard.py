import json

import tlsh

from utils import get_family


def jaccard_similarity(x, y):
    set1 = set(x)
    set2 = set(y)

    intersection = len(set1.intersection(set2))
    return float(intersection) / (len(set1) + len(set2) - intersection)


def print_readable(output_file_path):
    json_records = json.loads(open(output_file_path, "r").read())
    with open(output_file_path[:-5] + "_read.json", "w") as det_file:
        for rec in json_records:
            det_file.write(json.dumps(rec) + "\n")


def apk_candidate_neighbors(database_json, test_json_rec):
    apk_detections = dict()

    for db_json_rec in database_json:
        if len(db_json_rec["hashes"]) > 0:
            j = jaccard_similarity(test_json_rec["hashes"], db_json_rec["hashes"])
        else:
            print(db_json_rec["id"] + " does not have hashes")
        try:
            dex_s = tlsh.diff(test_json_rec["dex_fuzzy"], db_json_rec["dex_fuzzy"])
            perms_s = tlsh.diff(test_json_rec["perms_fuzzy"], db_json_rec["perms_fuzzy"])
        except:
            # If an apk does not have the dex or androidmanifest file
            print(test_json_rec["id"] + ": " + test_json_rec["dex_fuzzy"] + "\t" +
                  db_json_rec["id"] + ": " + db_json_rec["dex_fuzzy"])
        # Pre filtering for classification speed-up
        if j > 0:
            apk_detections[db_json_rec["id"]] = (j, dex_s, perms_s)
        elif dex_s < 70 and perms_s < 35:
            apk_detections[db_json_rec["id"]] = (j, dex_s, perms_s)

    return apk_detections


def compute_jaccard(database_json, testset_json, output_file_path):
    detections_list = list()

    for test_json_rec in testset_json:
        if len(test_json_rec["hashes"]) > 0:
            apk_detections = apk_candidate_neighbors(database_json, test_json_rec)
            detections_list.append({"id": test_json_rec["id"], "similarities": apk_detections})
        else:
            print(test_json_rec["id"] + " does not have hashes")

    json_list = json.dumps(detections_list)
    open(output_file_path, "w").write(json_list)
    # print_readable(output_file_path)

    return json.loads(json_list)

if __name__ == '__main__':
    print_readable("/home/pret/workspace/PycharmProjects/monalizza-v2/all_benign/jaccard_scores.json")