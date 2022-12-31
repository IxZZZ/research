from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit

class JavascriptInterfaceExtractor(IScript):

    def __init__(self):
        self.context = None
        self.units = None

    def run(self, ctx):
        self.context = ctx.getEnginesContext()
        if not self.context:
            return
        self.units = RuntimeProjectUtil.findUnitsByType(self.context.getProjects()[0], IJavaSourceUnit, False)
        if self.units:
            for unit in self.units:
                if clazz := unit.getClassElement():
                    self.extractAnnotation(clazz)
    
    def extractAnnotation(self, clazz):
        """
        := Identify and extract methods that are annotated with @JavascriptInterface
        """
        if methods := clazz.getMethods():
            for m in methods:
                if annotations := m.getMethodAnnotations():
                    for a in annotations:
                        if "JavascriptInterface" in a.getType().getSignature():
                            print("@JavacriptInterface")
                            print(m.getSignature().replace('L', '').replace('/', '.').replace(';', ''))
                            print("\n")
