from langgraph.graph import StateGraph, START, END

from app.state import AnalysisState
from app.graph_nodes import(
    run_language_step,
    run_attachment_step,
    run_email_structure_step,
    run_url_step,
    run_verdict_step,
)

def build_analysis_graph():
    graph = StateGraph(AnalysisState)

    graph.add_node("url_agent", run_url_step)
    graph.add_node("language_agent", run_language_step)
    graph.add_node("attachment_agent", run_attachment_step)
    graph.add_node("email_structure_agent", run_email_structure_step)
    graph.add_node("verdict_agent", run_verdict_step)

    graph.add_edge(START, "url_agent")
    graph.add_edge("url_agent", "language_agent")
    graph.add_edge("language_agent", "attachment_agent")
    graph.add_edge("attachment_agent", "email_structure_agent")
    graph.add_edge("email_structure_agent", "verdict_agent")
    graph.add_edge("verdict_agent", END)

    return graph.compile()

analysis_graph = build_analysis_graph()

def run_analysis_workflow(state: AnalysisState) -> AnalysisState:
    result = analysis_graph.invoke(state)
    return result