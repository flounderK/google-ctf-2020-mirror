
import angr
import claripy
import monkeyhex


project = angr.Project('a.out')

# initial_state = project.factory.blank_state(addr=)
buf_len = 16
stdin_bvs = claripy.BVS('stdin_bvs', buf_len*8)

initial_state = project.factory.entry_state(stdin=stdin_bvs)

for b in stdin_bvs.chop(8):
    initial_state.add_constraints(claripy.And(b >= 0x20, b < 0x7f))

simgr = project.factory.simgr(initial_state)


def is_success(s):
    return s.posix.dumps(1).find(b'SUCCESS') > -1


simgr.explore(find=is_success)

print(simgr.one_found.solver.eval(stdin_bvs, cast_to=bytes).decode())
