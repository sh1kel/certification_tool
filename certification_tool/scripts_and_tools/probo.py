from fuelweb_test.tests import test_simple
from proboscis import TestProgram, TestPlan
from proboscis.decorators import DEFAULT_REGISTRY

tp = TestProgram()

plan = TestPlan.create_from_registry(DEFAULT_REGISTRY)
plan.filter(group_names=['certification'])

names = [
         for case in plan.tests
         if 'certification' in case.entry.info.groups]

print names

def update_test_program(tp):
    tr = tp._TestProgram__run.func_closure[8].cell_content
    mr = tr._makeResult

    def newmr():
        tp.hidden_res = mr()
        return tp.hidden_res

    tr._makeResult = newmr
