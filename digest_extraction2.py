import hashlib
import json
import zipfile
import pathlib
import tlsh

from utils import get_files, get_family


def get_apk_id(apk):
    return apk


def print_readable_json(raw_json_file):
    with open(raw_json_file[:-5]+"_readable.json", "w") as fuzzy_hashes_file:
        for record in json.loads(open(raw_json_file, "r").read()):
            fuzzy_hashes_file.write(json.dumps(record)+"\n")


def is_valid_file(file_name):
    return not file_name.startswith(("classes.dex", "AndroidManifest.xml", "META-INF"))


def generate_apk_fuzzy_list(apk):
    apk_digests_list = list()
    dex_fuzzy = ""
    manifest_perms_fuzzy = ""

    try:
        with zipfile.ZipFile(apk, 'r') as zf:
            archive_elements = [(data.filename, data.file_size) for data in zf.filelist]
            for resource, res_size in archive_elements:
                if is_valid_file(resource):
                    bfile = zf.read(resource)
                    apk_digests_list.append(hashlib.sha256(bfile).hexdigest())
                elif resource == "classes.dex":
                    bfile = zf.read(resource)
                    dex_fuzzy = tlsh.hash(bfile)
                elif resource == "AndroidManifest.xml":
                    bfile = zf.read(resource)
                    manifest_perms_fuzzy = tlsh.hash(bfile)

    except zipfile.BadZipfile as e:
        print(str(e.args) + "\t" + apk)

    return get_apk_id(apk), apk_digests_list, dex_fuzzy, manifest_perms_fuzzy


def initialize_database(data_folder, logs_folder):
    records_list = list()
    apks = get_files(data_folder)
    fams_freq = dict()  # fam: |variants|

    for apk in apks:
        apk_id, apk_hashes, dex_fuzzy, perms_fuzzy = generate_apk_fuzzy_list(apk)
        records_list.append({"id": apk_id, "hashes": apk_hashes, "dex_fuzzy": dex_fuzzy, "perms_fuzzy": perms_fuzzy})
        try:
            fams_freq[get_family(apk)] += 1
        except KeyError:
            fams_freq[get_family(apk)] = 1

    json_list = json.dumps(records_list)
    # Store data
    pathlib.Path(logs_folder).mkdir(parents=True, exist_ok=True)
    open(logs_folder+"/hashes_database.json", "w").write(json_list)
    open(logs_folder+"/families_frequency.json", "w").write(json.dumps(fams_freq))

    return json.loads(json_list)


def generate_fuzzy_hashes(folder, logs_folder):
    records_list = list()
    apks = get_files(folder)

    for apk in apks:
        apk_id, apk_hashes, dex_fuzzy, perms_fuzzy = generate_apk_fuzzy_list(apk)
        records_list.append({"id": apk_id, "hashes": apk_hashes, "dex_fuzzy": dex_fuzzy, "perms_fuzzy": perms_fuzzy})

    # Store data
    json_list = json.dumps(records_list)
    # Store data
    pathlib.Path(logs_folder).mkdir(parents=True, exist_ok=True)
    open(logs_folder+"/hashes_testset.json", "w").write(json_list)

    return json.loads(json_list)
