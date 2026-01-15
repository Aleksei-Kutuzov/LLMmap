import typer

info_color = typer.colors.BLUE
success_color = typer.colors.GREEN
warn_color = typer.colors.YELLOW
error_color = typer.colors.RED

def info(message):
    typer.secho(message, fg=info_color)

def success(message):
    typer.secho(message, fg=success_color)

def warning(message):
    typer.secho(message, fg=warn_color)

def error(message):
    typer.secho(message, fg=error_color)

