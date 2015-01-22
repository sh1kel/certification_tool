from certification_tool.core.cert_script import base
from proboscis import TestProgram

# from proboscis import TestPlan
# from proboscis.decorators import DEFAULT_REGISTRY


def update_test_program(tp):
    "dirty-dirty-dirty hack, but proboscis don't provide any other way"

    tr = tp._TestProgram__run.func_closure[8].cell_contents
    mr = tr._makeResult

    def newmr():
        tp.hidden_res = mr()
        return tp.hidden_res

    tr._makeResult = newmr


class IntegrationTests(base.BaseTests):

    def run_test(self, test_name):
        from fuelweb_test.tests import test_simple

        assert test_name == "integration"

        with open('/dev/null', "w") as fd:
            tp = TestProgram(stream=fd, groups=['certification'])

            update_test_program(tp)

            try:
                tp.run_and_exit()
            except SystemExit:
                pass

            for (meth, msg) in tp.hidden_res.errors:
                test_method_name = str(meth).split('(')[1].split(')')[0]
                yield {'name': test_method_name,
                       'status': 'error',
                       'message': msg}

    def run_tests(self, tests):
        for test_name in tests:
            for res in self.run_test(test_name):
                yield res

    def get_available_tests(self):
        # plan = TestPlan.create_from_registry(DEFAULT_REGISTRY)
        # plan.filter(group_names=['certification'])
        # names = [
        #          for case in plan.tests
        #          if 'certification' in case.entry.info.groups]
        return ['integration']

# for res in IntegrationTests(None, None, None).run_tests(['integration']):
#     print res['name'], res['status']
