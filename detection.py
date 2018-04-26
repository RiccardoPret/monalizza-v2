import json
import os

from utils import get_family

THRESHOLD1 = 0.23
THRESHOLD2 = 0.5
FRACTION = 6  # If there are more than (or exactly) 1/FRACTION of total variants, use thr1 for that family for that app
TRUSTED_NUM_REPRESENTATIVES = 5  # If there are less variants in the db, without looking to neighbours, the higher threshold is used
TOP_NEIGHBOURS = 5  # Top neighbours used to find the proper family for the unknown sample


def get_fams_freq_neighbors(neighbors):
    """
    Get number of variants for each family
    :param neighbors: {db_mlw: (a,b,c), ...}
    :return:
    """
    neighbors_fam_freq = dict()
    for n in neighbors.keys():
        try:
            neighbors_fam_freq[get_family(n)] += 1
        except:
            neighbors_fam_freq[get_family(n)] = 1
    return neighbors_fam_freq


def get_custom_fam_threshold(neighbors_fam_freq, db_fams_freq):
    fams_threshold = dict()
    for fam, freq in neighbors_fam_freq.items():
        if db_fams_freq[fam] >= TRUSTED_NUM_REPRESENTATIVES:
            if freq >= db_fams_freq[fam]/FRACTION:
                fams_threshold[fam] = THRESHOLD1
            else:
                fams_threshold[fam] = THRESHOLD2
        else:
            fams_threshold[fam] = THRESHOLD2
    return fams_threshold


def filter_phase_jaccard(json_detections, data_folder):
    db_fams_freq = json.loads(open(data_folder+"/families_frequency.json", "r").read())
    json_filtered_neighbors = list()
    no_malware = list()

    for test_set_record in json_detections:
        good_neighbors = dict()
        db_neighbors = test_set_record["similarities"]
        # Filter good neighbors. It may be that they are empty after the filter phase in detect_mlw method
        if len(db_neighbors) > 0:
            neighbors_fams_freq = get_fams_freq_neighbors(db_neighbors)
            fams_thr = get_custom_fam_threshold(neighbors_fams_freq, db_fams_freq)
            for mlw_db, sim_scores in db_neighbors.items():
                fam = get_family(mlw_db)
                if sim_scores[0] > fams_thr[fam]:
                    good_neighbors[mlw_db] = sim_scores[0]

        # Check if it is a malware or not
        if len(good_neighbors) == 0:
            no_malware.append(test_set_record["id"])
        else:
            json_filtered_neighbors.append({"id": test_set_record["id"], "good_neighbors": good_neighbors})

    return json_filtered_neighbors, no_malware


def print_neighbors(apk, neighbors, file_name):
    with open(file_name, "a") as nf:
        tup = (apk, list(neighbors))
        nf.write(str(tup)+"\n")


def compute_sample_family(top_neighbors):
    fams = dict()
    for n, jaccard in top_neighbors:
        try:
            fams[get_family(n)] += 1*jaccard
        except:
            fams[get_family(n)] = jaccard
    fams_tup = sorted(fams.items(), key=lambda x: -x[1])
    return fams_tup[0][0]


def filter_jaccard_zero(json_detections):
    new_records_list = list()
    for test_set_record in json_detections:
        new_neighbors = dict()
        similarities = test_set_record["similarities"]
        for mlw_db, tuple_scores in similarities.items():
            if tuple_scores[0] > 0:
                new_neighbors[mlw_db] = tuple_scores
        new_records_list.append({"id": test_set_record["id"], "similarities": new_neighbors})

    return json.loads(json.dumps(new_records_list))


def get_not_yet_classified(json_full, non_classified_ids):
    json_remained = list()
    for record in json_full:
        if record["id"] in non_classified_ids:
            json_remained.append(record)
    return json_remained


def filter_phase_dex_perms(json_remained):
    json_filtered = list()
    no_malware = list()

    for record in json_remained:
        neighbors = record["similarities"]
        good_neighbors = dict()
        for mlw_db, scores_tuple in neighbors.items():
            if scores_tuple[1] < 70 and scores_tuple[2] < 35:
                good_neighbors[mlw_db] = scores_tuple
        if len(good_neighbors) > 0:
            json_filtered.append({"id": record["id"], "good_neighbors": good_neighbors})
        else:
            no_malware.append(record["id"])
    return json_filtered, no_malware


def compute_family_second(apk_neighbors):
    neighbors_fam = dict()
    for neighbor in apk_neighbors:
        try:
            neighbors_fam[get_family(neighbor)] += 1
        except:
            neighbors_fam[get_family(neighbor)] = 1
    return sorted(neighbors_fam.items(), key=lambda x: x[0])[0][0]


def detection_mlw(json_detections, results_file_path):
    classifications = dict()
    neighbors_file_name = os.path.split(results_file_path)[0]+"/samples_neighbors.txt"
    if os.path.exists(neighbors_file_name):
        os.remove(neighbors_file_name)

    # Remove neighbors with jaccard = 0 but with similarities with dex or permissions.
    # They do not need to be counted in the classification process that looks at jaccard
    no_zero_jaccards = filter_jaccard_zero(json_detections)
    filtered_samples, no_malware = filter_phase_jaccard(no_zero_jaccards, os.path.split(results_file_path)[0])

    # First classification
    for detection in filtered_samples:
        apk_id = detection["id"]
        apk_neighbors = detection["good_neighbors"]
        top_neighbors = sorted(apk_neighbors.items(), key=lambda x: -x[1])[:TOP_NEIGHBOURS]
        classifications[apk_id] = compute_sample_family(top_neighbors)
        print_neighbors(apk_id, [apk for apk, j in top_neighbors], neighbors_file_name)
    '''
    # Second classification
    json_remained = get_not_yet_classified(json_detections, no_malware)
    filtered_samples, no_malware = filter_phase_dex_perms(json_remained)

    for detection in filtered_samples:
        apk_id = detection["id"]
        apk_neighbors = detection["good_neighbors"]
        classifications[apk_id] = compute_family_second(apk_neighbors)
    '''
    with open(results_file_path, "w") as class_file:
        for apk, family in classifications.items():
            tup = (apk, family)
            class_file.write(str(tup)+"\n")
        for apk in no_malware:
            tup = (apk, "safe")
            class_file.write(str(tup)+"\n")
    return classifications
