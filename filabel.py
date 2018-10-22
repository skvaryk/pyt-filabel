from __future__ import print_function
import click
import configparser
import requests
import json
import re
import fnmatch
import sys


class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


@click.command()
@click.option('-s', '--state', type=click.Choice(['open', 'closed', 'all']),
              show_default=True, default='open', help='Filter pulls by state.')
@click.option('-d/-D', '--delete-old/--no-delete-old', default=True, is_flag=True,
              show_default=True, help='Delete labels that do not match anymore.')
@click.option('-b', '--base', metavar='BRANCH',
              help='Filter pulls by base (PR target) branch name.')
@click.option('-a', '--config-auth', metavar="FILENAME", type=click.Path(),
              help='File with authorization configuration.')
@click.option('-l', '--config-labels', metavar="FILENAME", type=click.Path(),
              help='File with labels configuration.')
@click.argument('reposlugs', nargs=-1, required=False)
def main(state, delete_old, base, config_auth, config_labels, reposlugs):
    """CLI tool for filename-pattern-based labeling of GitHub PRs"""
    checkArgs(config_auth, config_labels, reposlugs)
    configs = parseConfigs(config_auth, config_labels)
    session = setupSession(configs[0]['token'])
    for slug in reposlugs:
        markSlugWithLabels(session, slug, configs[1], delete_old, state, base)


def checkArgs(config_auth, config_labels, reposlugs):
    if(not config_auth):
        eprint('Auth configuration not supplied!')
        eprint('Error: Missing option "-a" / "--config-auth".')
        exit(1)

    parser = configparser.ConfigParser()
    with open(config_auth) as auth_file:
        parser.read_file(auth_file)

    if(not parser or not parser.has_section('github')):
        eprint('Auth configuration not usable!')
        exit(1)

    if(not config_labels):
        eprint('Labels configuration not supplied!')
        eprint('Error: Missing option "-l" / "--config-labels".')
        exit(1)

    with open(config_labels) as labels_file:
        parser.read_file(labels_file)

    if(not parser or not parser.has_section('labels')):
        eprint('Labels configuration not usable!')
        exit(1)

    for slug in reposlugs:
        if(len(slug.split('/')) != 2):
            eprint('Reposlug {} not valid!'.format(slug))
            exit(1)


def parseConfigs(config_auth, config_labels):
    parser = configparser.ConfigParser()
    with open(config_auth) as auth_file:
        parser.read_file(auth_file)
    with open(config_labels) as labels_file:
        parser.read_file(labels_file)
    auth = parser['github']
    labels = parser['labels']
    checkParsedConfigs(auth, labels)
    return (auth, labels)


def checkParsedConfigs(auth, labels):
    if(not auth['token']):
        print('Auth configuration not usable!')
        exit(1)


def setupSession(token):
    session = requests.Session()
    session.headers = {'User-Agent': 'Python'}
    session.headers['Authorization'] = 'token ' + token
    return session


def markSlugWithLabels(session, slug, labels_config, delete_old, state, base=None):
    if(checkRepoSlug(session, slug)):
        # print(color.BOLD + "REPO " + color.END + slug + " - " +
        #       color.BOLD + color.GREEN + "OK" + color.END)
        print("REPO {} - OK".format(slug))
    else:
        print("REPO {} - FAIL".format(slug))
        # print(color.BOLD + "REPO " + color.END + slug + " - " +
        #       color.BOLD + color.RED + "FAIL" + color.END)
        return

    owner = slug.split('/')[0]
    repo = slug.split('/')[1]

    pr_numbers = []
    pr_labels = []

    for i in range(1, 10):

        url = getPullsUrl(owner, repo, state, base, i)
        response = session.get(url)
        if(not response.ok):
            print("REPO {} - FAIL".format(slug))
            return
        json_data = json.loads(response.text)
        if(not json_data):
            continue

        for pr in json_data:
            pr_numbers.append(pr['number'])
            pr_labels_name_list = list()
            labels_list_of_dicts = pr['labels']
            if(labels_list_of_dicts):
                for label_dict in labels_list_of_dicts:
                    pr_labels_name_list.append(label_dict['name'])
            pr_labels.append(pr_labels_name_list)

    for i in range(0, len(pr_numbers)):
        # print(color.BOLD + "  PR " + color.END + "https://github.com/{}/pull/{}".format(
        #     slug, pr_numbers[i]) + " - " + color.BOLD + color.GREEN + "OK" + color.END)
        markPrWithLabels(session, owner, repo, state, base,
                         pr_numbers[i], pr_labels[i], labels_config, delete_old)


def checkRepoSlug(session, reposlug):
    owner = reposlug.split('/')[0]
    repo = reposlug.split('/')[1]
    url = getPullsUrl(owner, repo, 'all', None, 1)
    response = session.get(url)
    return response.ok


def markPrWithLabels(session, owner, repo, state, base, pr_number,
                     old_labels, labels_config, delete_old):

    files = getFilesFromPr(session, owner, repo, pr_number, state, base)
    new_labels = getLabelsFromFiles(files, labels_config)
    all_labels = getAllLabels(
        labels_config, old_labels, new_labels, delete_old)
    if(not all_labels[0]):
        printPrResult(owner, repo, pr_number, True)
        return
    url = getUpdateLabelsUlr(owner, repo, pr_number)
    data = getLabelsPatchData(all_labels[0], all_labels[1])
    response = session.patch(url, data)
    if(not response.ok):
        printPrResult(owner, repo, pr_number, False)
        return
    response_json = json.loads(response.text)
    successful_labels = list()
    successful_labels_array = response_json['labels']
    for successful_label_json in successful_labels_array:
        if(not successful_label_json):
            continue
        successful_labels.append(successful_label_json['name'])
    for i in range(0, len(all_labels[0])):
        if(all_labels[1][i] == -1):
            continue
        if(all_labels[0][i] not in successful_labels):
            printPrResult(owner, repo, pr_number, False)
            return

    if(response.ok):
        printPrResult(owner, repo, pr_number, True)
    else:
        printPrResult(owner, repo, pr_number, False)
        return
    for i in range(0, len(all_labels[0])):
        if(all_labels[1][i] == 1):
            # print(color.GREEN + "    + " + final_labels[0][i] + color.END)
            print("    + " + all_labels[0][i])
        elif(all_labels[1][i] == -1):
            # print(color.RED + "    - " + final_labels[0][i] + color.END)
            print("    - " + all_labels[0][i])
        elif(all_labels[0][i] in labels_config and delete_old):
            # print("    = " + final_labels[0][i])
            print("    = " + all_labels[0][i])


def getFilesFromPr(session, owner, repo, pr_number, state, base):
    filenames = []
    for i in range(1, 10):
        files_url = getFilesUrl(owner, repo, pr_number, state, base, i)
        files_response = session.get(files_url)
        json_files = json.loads(files_response.text)
        if(not json_files):
            break

        for json_file in json_files:
            filenames.append(json_file['filename'])
    return filenames


def getLabelsFromFiles(files, labels_config):
    labels_set = set()
    for label in labels_config:
        for fn_string in labels_config[label].splitlines():
            if(fn_string):
                regex = fnmatch.translate(fn_string)
                matcher = re.compile(regex)
                for filename in files:
                    if(matcher.match(filename)):
                        labels_set.add(label)
    return labels_set


def getAllLabels(labels_config, old_labels, new_labels, delete_old):
    old_labels_to_delete = set()
    old_labels_to_keep = set()
    if(delete_old):
        old_labels_to_delete = set(getOldLabelsToDelete(
            labels_config, old_labels, new_labels))
        old_labels_to_keep = set(old_labels).difference(
            set(old_labels_to_delete))
    else:
        old_labels_to_keep = set(old_labels)
    all_labels = sorted(set(old_labels).union(new_labels))
    state_list = list()
    for label in all_labels:
        if(label in old_labels_to_keep):
            state_list.append(0)
        elif(label in new_labels):
            state_list.append(1)
        else:
            state_list.append(-1)
    return (all_labels, state_list)


def getOldLabelsToDelete(labels_config, old_labels, new_labels):
    labels_to_delete = []
    for label in labels_config:
        if(label in old_labels and label not in new_labels):
            labels_to_delete.append(label)
    return labels_to_delete

def printPrResult(owner, repo, pr_number, is_ok):
    output = "  PR https://github.com/{}/{}/pull/{} - "
    if(is_ok):
        output = output + "OK"
    else:
        output = output + "FAIL"

    print(output.format(owner, repo, pr_number))


def getPullsUrl(owner, repo, state, base, page):
    url = 'https://api.github.com/repos/{}/{}/pulls?state={}&owner={}&page={}'.format(
        owner, repo, state, owner, page)
    return addBaseToUrl(url, base)


def getFilesUrl(owner, repo, number, state, base, page):
    url = 'https://api.github.com/repos/{}/{}/pulls/{}/files?state={}&page={}&per_page=300&owner={}'.format(
        owner, repo, number, state, page, owner)
    return addBaseToUrl(url, base)


def getUpdateLabelsUlr(owner, repo, number):
    url = 'https://api.github.com/repos/{}/{}/issues/{}'.format(
        owner, repo, number)
    return url


def getLabelsPatchData(labels, states):
    result = list()
    for i in range(0, len(labels)):
        if(states[i] == 1):
            result.append(labels[i])
        elif(states[i] == 0):
            result.append(labels[i])
    labels_str = str(result)
    labels_arg = labels_str.replace('\'', '"')
    body = '{"labels": ' + labels_arg + '}'
    return body


def addBaseToUrl(url, base):
    if(base != None):
        url = url + '&base=' + base
    return url


if __name__ == '__main__':
    main()
