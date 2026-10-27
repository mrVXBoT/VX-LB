#!/usr/bin/env python3
"""Validate, render or publish the reviewed docs/wiki pages to GitHub Wiki."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'docs/wiki'
LINK = re.compile(r'(?<!!)\[([^\]]+)\]\(([^)\s]+)\)')


def pages():
    result={p.name:p.read_text() for p in SOURCE.glob('*.md')}
    if not {'Home.md','_Sidebar.md','_Footer.md'} <= result.keys():
        raise ValueError('Wiki Home/sidebar/footer missing')
    for name,text in result.items():
        for _,target in LINK.findall(text):
            if target.startswith(('https://','http://','mailto:','#')):
                continue
            filename=target.split('#',1)[0]
            if filename not in result:
                raise ValueError(f'Broken or non-portable link in {name}: {target}')
    return result


def render(text):
    def link(match):
        title,target=match.groups()
        if target.startswith(('https://','http://','mailto:','#')):
            return match.group()
        filename,sep,fragment=target.partition('#')
        return f'[{title}]({filename.removesuffix(".md")}{sep}{fragment})'
    return LINK.sub(link,text)


def write(destination, contents):
    destination.mkdir(parents=True,exist_ok=True)
    for name,text in contents.items():
        (destination/name).write_text(render(text))


def run(*arguments,cwd=None):
    result=subprocess.run(arguments,cwd=cwd,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'Command failed')
    return result.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group()
    action.add_argument('--output',type=Path,help='Render extensionless Wiki links locally; no network')
    action.add_argument('--publish',action='store_true',help='Commit and push reviewed pages to existing Wiki')
    parser.add_argument('--repository',default='mrVXBoT/VX-LB')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',args.repository):
        parser.error('Repository must be owner/name')
    contents=pages()
    if args.output:
        if args.output.resolve()==SOURCE.resolve():
            parser.error('Render output must be separate from source')
        write(args.output,contents)
        print(f'Rendered {len(contents)} Wiki pages to {args.output}')
    elif args.publish:
        with tempfile.TemporaryDirectory(prefix='vxlb-wiki-') as temp:
            clone=Path(temp)/'wiki'
            try:
                run('git','clone','--quiet',f'https://github.com/{args.repository}.wiki.git',str(clone))
            except RuntimeError as error:
                raise RuntimeError('Wiki clone failed. Initialize the first Home page through GitHub Wiki, and verify write access. '+str(error)) from error
            write(clone,contents)
            run('git','add','--',*contents.keys(),cwd=clone)
            if not run('git','diff','--cached','--name-only',cwd=clone).strip():
                print('Wiki already matches reviewed documentation')
                return
            run('git','-c','user.name=VX-LB Documentation','-c','user.email=docs@users.noreply.github.com',
                'commit','--quiet','-m','Publish comprehensive Persian VX-LB user guide',cwd=clone)
            run('git','push','origin','HEAD',cwd=clone)
            print(f'Published {len(contents)} pages: https://github.com/{args.repository}/wiki')
    else:
        print(f'Validated links and structure for {len(contents)} Wiki pages')

if __name__=='__main__':
    try:
        main()
    except (ValueError,RuntimeError) as error:
        raise SystemExit(str(error))
