with open("tests/test_cli.py") as f:
    c = f.read()

c = c.replace("get_reporter", "get")

with open("tests/test_cli.py", "w") as f:
    f.write(c)

with open("tests/test_core.py") as f:
    c2 = f.read()

c2 = c2.replace("reg.list()", "reg.list(BaseAttack)")
c2 = c2.replace('match="Unknown attack"', 'match="Unknown BaseAttack"')

with open("tests/test_core.py", "w") as f:
    f.write(c2)
