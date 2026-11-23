from pathlib import Path

from streamlit.testing.v1 import AppTest

from modules.lab_ui import LAB_PAGE
from modules.shell import MORE, PAGES, TOOLS
from modules.ui import visible_label


APP = Path(__file__).resolve().parents[1] / "app.py"


def element(widgets, label):
    return next(widget for widget in widgets if widget.label == label)


def go(app, page):
    navigation = element(app.sidebar.radio, "Primary navigation")
    if page in TOOLS:
        navigation.set_value(MORE).run()
        element(app.sidebar.selectbox, "Specialist tools").set_value(page).run()
    else:
        navigation.set_value(page).run()
    assert not app.exception, page
    return app


def create_case(app, name):
    go(app, "Investigations")
    element(app.text_input, "Investigation name").set_value(name)
    element(app.button, "Create investigation").click().run()
    return element(app.selectbox, "Investigation").value


def test_pages_and_investigation_workflow(app_environment):
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    assert app.title[0].value == "Investigation Overview"
    assert element(app.button, "Start investigation")
    case = create_case(app, "Test investigation")
    assert case
    assert app.query_params["case"] == case
    element(app.button_group, "Interface mode").set_value("Advanced").run()
    for page in PAGES:
        go(app, page)
        assert not app.error, page
        title = "Investigation Overview" if page == "Dashboard" else LAB_PAGE if page == LAB_PAGE else visible_label(page)
        assert app.title[0].value == title
    go(app, "Privacy Protection")
    element(app.button, "Protect selected records").click().run()
    assert app.dataframe
    go(app, "AI Forensic Analysis")
    element(app.button, "Score selected records").click().run()
    assert not app.exception
    assert not app.error
    assert len(app.dataframe) >= 3
    go(app, "Event Correlation")
    anchor = element(app.selectbox, "Inspect event timeline")
    anchor.select(anchor.options[0]).run()
    assert not app.exception
    assert not app.error
    assert element(app.selectbox, "Event on timeline")


def test_deep_link_and_modes_share_the_same_case(app_environment):
    app = AppTest.from_file(str(APP), default_timeout=30).run()
    case = create_case(app, "Shareable case")
    new = AppTest.from_file(str(APP), default_timeout=30)
    new.query_params.update(page="evaluation", case=case)
    new.run()
    assert new.title[0].value == LAB_PAGE
    assert element(new.selectbox, "Investigation").value == case
    assert element(new.selectbox, "Privacy method")
    assert all(widget.label != "Training epochs" for widget in new.number_input)
    element(new.button_group, "Interface mode").set_value("Advanced").run()
    assert element(new.number_input, "Training epochs")
    assert element(new.selectbox, "Investigation").value == case
