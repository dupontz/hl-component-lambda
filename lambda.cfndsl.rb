CloudFormation do

  functions.each do |function_name, lambda_config|
    if (lambda_config.has_key? 'enable_eni') && (lambda_config['enable_eni'])
      az_conditions_resources('SubnetCompute', maximum_availability_zones)
      break
    end
  end if defined? functions

  tags = []
  tags << { Key: 'Environment', Value: Ref(:EnvironmentName) }
  tags << { Key: 'EnvironmentType', Value: Ref(:EnvironmentType) }

  extra_tags.each { |key,value| tags << { Key: key, Value: value } } if defined? extra_tags

  functions.each do |function_name, lambda_config|

    policies = []
    lambda_config['policies'].each do |name,policy|
      policies << iam_policy_allow(name,policy['action'],policy['resource'] || '*')
    end if lambda_config.has_key?('policies')

    IAM_Role("#{function_name}Role") do
      AssumeRolePolicyDocument service_role_assume_policy('lambda')
      Path '/'
      Policies policies if policies.any?
      ManagedPolicyArns lambda_config['managed_policies'] if lambda_config.has_key?('managed_policies')
    end

    if (lambda_config.has_key? 'enable_eni') && (lambda_config['enable_eni'])
      EC2_SecurityGroup("#{function_name}SecurityGroup") do
        GroupDescription FnSub("${EnvironmentName}-lambda-#{function_name}")
        VpcId Ref('VPCId')
        Tags tags
      end

      Output("#{function_name}SecurityGroup") {
        Value(Ref("#{function_name}SecurityGroup"))
        Export FnSub("${EnvironmentName}-#{component_name}-#{function_name}SecurityGroup")
      }
    end

    environment = lambda_config['environment'] || {}

    # Create Lambda function
    Lambda_Function(function_name) do
      Code({
          S3Bucket: distribution['bucket'],
          S3Key: FnSub("#{distribution['prefix']}/#{lambda_config['code_uri']}")
      })

      Environment(Variables: Hash[environment.collect { |k, v| [k, v] }])

      Handler(lambda_config['handler'] || 'index.handler')
      MemorySize(lambda_config['memory'] || 128)
      Role(FnGetAtt("#{function_name}Role", 'Arn'))
      Runtime(lambda_config['runtime'])
      Timeout(lambda_config['timeout'] || 10)
      if (lambda_config.has_key? 'enable_eni') && (lambda_config['enable_eni'])
        VpcConfig({
          SecurityGroupIds: [
            Ref("#{function_name}SecurityGroup")
          ],
          SubnetIds: az_conditional_resources('SubnetCompute', maximum_availability_zones)
        })
      end

      if !lambda_config['named'].nil? && lambda_config['named']
        FunctionName(function_name)
      end
      Tags tags
    end

    Logs_LogGroup("#{function_name}LogGroup") do
      LogGroupName FnSub("/aws/lambda/${EnvironmentName}/#{function_name}")
      RetentionInDays lambda_config['log_retention'] if lambda_config.has_key? 'log_retention'
    end

    lambda_config['events'].each do |name,event|

      case event['type']
      when 'schedule'

        Events_Rule("#{function_name}Schedule#{name}") do
          ScheduleExpression event['expression']
          State event['disable'] ? 'DISABLED' : 'ENABLED'
          target = {
              Arn: FnGetAtt(function_name, 'Arn'),
              Id: "lambda#{function_name}"
          }
          target['Input'] = event['payload'] if event.key?('payload')
          Targets([target])
        end

        Lambda_Permission("#{function_name}#{name}Permissions") do
          FunctionName Ref(function_name)
          Action 'lambda:InvokeFunction'
          Principal 'events.amazonaws.com'
          SourceArn FnGetAtt("#{function_name}Schedule#{name}", 'Arn')
        end

      when 'sns'

        SNS_Topic("#{function_name}Sns#{name}") do
          Subscription([
            {
              Endpoint: FnGetAtt(function_name, 'Arn'),
              Protocol: 'lambda'
            }
          ])
        end

        Lambda_Permission("#{function_name}#{name}Permissions") do
          FunctionName Ref(function_name)
          Action 'lambda:InvokeFunction'
          Principal 'sns.amazonaws.com'
          SourceArn Ref("#{function_name}Sns#{name}")
        end

      when 'filter'

        Logs_SubscriptionFilter("#{function_name}SubscriptionFilter#{name}") do
          DestinationArn FnGetAtt(function_name, 'Arn')
          FilterPattern event['pattern']
          LogGroupName Ref(event['log_group'])
        end

        Lambda_Permission("#{function_name}#{name}Permissions") do
          FunctionName Ref(function_name)
          Action 'lambda:InvokeFunction'
          Principal FnSub('logs.${AWS::Region}.amazonaws.com')
          SourceAccount Ref('AWS::AccountId')
          SourceArn FnSub("arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/#{event['log_group']}:*")
        end

      end

    end if lambda_config.has_key?('events')


    service_loadbalancer = []
    # targetgroups = lambda_config['targetgroup'] if lambda_config.has_key?('targetgroup')
    # targetgroups = external_parameters.fetch(lambda_config['targetgroup'], {})
    targetgroups = external_parameters.fetch(:targetgroup, {})
    
    # print "aaa"

    print targetgroups
    rule_names = []
    unless targetgroups.empty?
  
      if !targetgroups.is_a?(Array)
        # Keep original resource names for backwards compatibility
        targetgroups['resource_name'] = targetgroup.has_key?('rules') ? 'TaskTargetGroup' : 'TargetGroup'
        targetgroups['listener_resource'] = 'Listener'
        targetgroups = [targetgroups]
      else
        # Generate resource names based upon the target group name and the listener and suffix with resource type
        targetgroups.each do |tg| 
          tg['resource_name'] = "#{tg['name'].gsub(/[^0-9A-Za-z]/, '')}TargetGroup"
          tg['listener_resource'] = "#{tg['listener']}Listener"
        end
      end
      targetgroups.each do |targetgroup|
        if targetgroup.has_key?('rules')
          attributes = []
    
          targetgroup['attributes'].each do |key,value|
            attributes << { Key: key, Value: value }
          end if targetgroup.has_key?('attributes')
    
          tg_tags = tags.map(&:clone)
    
          targetgroup['tags'].each do |key,value|
            tg_tags << { Key: key, Value: value }
          end if targetgroup.has_key?('tags')
    
          ElasticLoadBalancingV2_TargetGroup(targetgroup['resource_name']) do
            ## Optional
            if targetgroup.has_key?('healthcheck')
              HealthCheckPort targetgroup['healthcheck']['port'] if targetgroup['healthcheck'].has_key?('port')
              HealthCheckProtocol targetgroup['healthcheck']['protocol'] if targetgroup['healthcheck'].has_key?('port')
              HealthCheckIntervalSeconds targetgroup['healthcheck']['interval'] if targetgroup['healthcheck'].has_key?('interval')
              HealthCheckTimeoutSeconds targetgroup['healthcheck']['timeout'] if targetgroup['healthcheck'].has_key?('timeout')
              HealthyThresholdCount targetgroup['healthcheck']['healthy_count'] if targetgroup['healthcheck'].has_key?('healthy_count')
              UnhealthyThresholdCount targetgroup['healthcheck']['unhealthy_count'] if targetgroup['healthcheck'].has_key?('unhealthy_count')
              HealthCheckPath targetgroup['healthcheck']['path'] if targetgroup['healthcheck'].has_key?('path')
              Matcher ({ HttpCode: targetgroup['healthcheck']['code'] }) if targetgroup['healthcheck'].has_key?('code')
            end

            if targetgroup.has_key?('Targets')
              Targets = {
                Id: FnGetAtt(function_name, 'Arn')
              }

             
            end
    
            TargetType targetgroup['type'] if targetgroup.has_key?('type')
            TargetGroupAttributes attributes if attributes.any?
            

            Tags tg_tags
          end
          
          targetgroup['rules'].each_with_index do |rule, index|
            listener_conditions = []
            if rule.key?("path")
              listener_conditions << { Field: "path-pattern", Values: rule["path"]  }
            end
            if rule.key?("host")
              hosts = []
              if rule["host"].include?('.') || rule["host"].key?("Fn::Join")
                hosts << rule["host"]
              else
                hosts << FnJoin("", [ rule["host"], ".", Ref("EnvironmentName"), ".", Ref('DnsDomain') ])
              end
              listener_conditions << { Field: "host-header", Values: hosts }
            end
    
            if rule.key?("name")
              rule_name = rule['name']
            elsif rule['priority'].is_a? Integer
              rule_name = "TargetRule#{rule['priority']}"
            else
              rule_name = "TargetRule#{index}"
            end
            rule_names << rule_name
  
            actions = [{ Type: "forward", Order: 5000, TargetGroupArn: Ref(targetgroup['resource_name'])}]
            actions_with_cognito = actions + [cognito(Ref(:UserPoolId), Ref(:UserPoolClientId), Ref(:UserPoolDomainName))]
            ElasticLoadBalancingV2_ListenerRule(rule_name) do
              Actions  actions
              Conditions listener_conditions
              ListenerArn Ref(targetgroup['listener_resource'])
              Priority rule['priority']
            end
    
          end
        end
    
        # service_loadbalancer << {
        #   ContainerName: targetgroup['container'],
        #   ContainerPort: targetgroup['port'],
        #   TargetGroupArn: Ref(targetgroup['resource_name'])
        # }
      end
    end
  end if defined? functions



end
