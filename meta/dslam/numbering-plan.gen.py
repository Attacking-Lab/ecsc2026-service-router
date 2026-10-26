import argparse
import json
import pathlib

if __name__ == "__main__":
    # example usage: ./numbering-plan.gen.py teams.json 10.55.id.2
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", help="template file", type=pathlib.Path, default=pathlib.Path("./numbering-plan.yaml.template"))
    parser.add_argument("-o", "--output", help="output file", type=pathlib.Path, default=pathlib.Path("./numbering-plan.yaml"))
    parser.add_argument("teams", help="teams.json", type=pathlib.Path)
    parser.add_argument("pattern", help="vulnbox IP pattern, `id` is the team ID")
    args = parser.parse_args()

    template = args.template.read_text()
    with args.teams.open() as teams_file:
        teams = json.load(teams_file)

    for team in teams["teams"]:
        name = team["name"]
        team_id = team["team_id"]
        team_ip = args.pattern.replace("id", str(team_id))
        template = template.replace(f"<{name}>", f"{team_ip}")

    args.output.write_text(template)
