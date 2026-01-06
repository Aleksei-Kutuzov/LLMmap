import os
from typing import Dict

import yaml

from providers.config.cofig import Config, Endpoint, Request, Response, Authentication


def config_load(filename: str, params: Dict[str, str] | None) -> Config:
    with open(filename, 'r') as file:
        config = yaml.load(file, Loader=yaml.FullLoader)
    endpoint_config = Endpoint(url=config['endpoint']['url'],
                              method=config['endpoint']['method'],
                              headers=config['endpoint']['headers'],
                              parameters=config['endpoint']['parameters'])
    request_config = Request(system_prompt=config['request_template']['system_prompt'],
                            user_prompt=config['request_template']['user_prompt'],
                            temperature=config['request_template']['model_parameters']['temperature'],
                            max_tokens=config['request_template']['model_parameters']['max_tokens'],
                            top_p=config['request_template']['model_parameters']['top_p'],
                            model=config['request_template']['model_parameters']['model'],
                            stream=config['request_template']['model_parameters']['stream'])

    response_config = Response(content_path=config['response_template']['content_path'],
                              metadata=config['response_template']['metadata'],
                              error_codes=config['response_template']['error_codes'],
                              error_messages=config['response_template']['error_messages'],
                              )

    authentication_config = Authentication(type=config['authentication'].get('type'),
                                          location=config['authentication'].get('location'),
                                          field=config['authentication'].get('field'),
                                          format=config['authentication'].get('format'),
                                          env_vars=None)

    if authentication_config.type != 'none':
        envVars = {}
        for key in config['authentication'].get('env_vars').keys():
            if params.get(config['authentication'].get('env_vars').get(key)):
                envVars[key] = params.get(config['authentication'].get('env_vars').get(key))
            else:
                envVars[key] = os.environ.get(config['authentication'].get('env_vars').get(key))
            if not envVars[key]:
                envVars[key] = "None"
        authentication_config.env_vars = envVars

        if authentication_config.location == 'header':
            key = authentication_config.format[authentication_config.format.index("{")+1:authentication_config.format.index("}")]
            endpoint_config.headers[authentication_config.field] = authentication_config.format[:authentication_config.format.index("{")] + envVars.get(key) + authentication_config.format[authentication_config.format.index("}")+1:]

    modelConfig = Config(endpoint=endpoint_config,
                         request=request_config,
                         response=response_config,
                         authentication=authentication_config)

    return modelConfig

if __name__ == '__main__':
    config = config_load(r'/config_template.yaml', {"API_KEY": "123"})
    print(config)