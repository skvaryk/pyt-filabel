import click
import configparser


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
    print(state)


def checkArgs(config_auth, config_labels, reposlugs):
    if(config_auth == None):
        print('Auth configuration not supplied!')
        exit(1)
    if(config_labels == None):
        print('Labels configuration not supplied!')
        exit(1)
    for slug in reposlugs:
        if(len(slug.split('/')) != 2):
            print('Reposlug {} not valid!'.format(slug))
            exit(1)

def parseConfigs(config_auth, config_labels):
    parser=configparser.ConfigParser()
    parser.read(config_auth)
    parser.read(config_labels)
    print(parser['github']['token'])
    print(parser['labels']['frontend'])
    return (parser['github'], parser['labels'])


if __name__ == '__main__':
    main()
