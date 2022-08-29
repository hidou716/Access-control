pragma solidity ^0.8.7;

 contract AccessControl{
address public owner;

event ReturnAccessResult( address indexed _from, string _errmsg, uint _penalty, bool _result, uint time);

struct registration {
    uint id;
    bool isValued;
}
 struct PolicyItem{ //for one (resource, action) pair;
 bool isValued; //for duplicate check
 string permission; //permission: "allow" or "deny"
 uint minInt; //minimum allowable interval (in seconds) between two successive requests
 uint ToLR; //Time of Last Request
 uint NoFR; //Number of frequent Requests in a short period of time
 uint Limit; //Limit on NoFR, above which a misbehavior is suspected

 }
 
 struct Misconduct{
string resource ; //resource on which the misbehavior is conducted
 string action; //action (e.g., "read", "write", "execute") of the misbehavior
 uint timeoM; //time of the misbehavior occured
 uint penalty; //penalty opposed to the subject (number of minutes blocked)
 }
 struct MisconductList{ //for one resource
 Misconduct [] mbs; //misbehavior list of the subject on a particular resource
uint TimeofUnblock; //time when the resource is unblocked (0 if unblocked; otherwise, blocked)
}
 

 mapping (address => mapping(string =>mapping(string => PolicyItem))) SubjectPolicies; //mapping (adress, resource, action) => for policy check
 mapping (address => MisconductList) SubjectMisconductList; //for Misconduct check
 mapping(address => registration ) SubjectRegistration; // for registration check

 constructor() {
        owner = msg.sender;
        
        
 }
     
     
function policyAdd(address _subject, string memory _resource, string memory _action, string memory _permission, uint _minInt, uint _Limit) public{
require (msg.sender == owner);
require (SubjectPolicies[_subject][_resource][_action].isValued == false); //duplicated key
SubjectPolicies[_subject][_resource][_action].permission= _permission;
SubjectPolicies[_subject][_resource][_action].minInt= _minInt;
SubjectPolicies[_subject][_resource][_action].Limit= _Limit;
SubjectPolicies[_subject][_resource][_action].ToLR= 0;
SubjectPolicies[_subject][_resource][_action].NoFR=0;
SubjectPolicies[_subject][_resource][_action].isValued= true;

 }
 
function getPolicy(address _subject, string memory _resource, string memory _action) public view returns (string memory _permission, uint _minInt, uint _Limit, uint _ToLR, uint _NoFR){
require (SubjectPolicies[_subject][_resource][_action].isValued == true); 
 _permission = SubjectPolicies[_subject][_resource][_action].permission;
 _minInt = SubjectPolicies[_subject][_resource][_action].minInt;
 _Limit = SubjectPolicies[_subject][_resource][_action].Limit;
 _NoFR = SubjectPolicies[_subject][_resource][_action].NoFR;
 _ToLR = SubjectPolicies[_subject][_resource][_action].ToLR;
 

 }   
 function policyUpdate(address _subject, string memory _resource, string memory _action, string memory _newPermission, uint _newminInt, uint _newLimit) public{
require (SubjectPolicies[_subject][_resource][_action].isValued == true); 
SubjectPolicies[_subject][_resource][_action].permission = _newPermission;
SubjectPolicies[_subject][_resource][_action].minInt= _newminInt;
SubjectPolicies[_subject][_resource][_action].Limit = _newLimit;
 }  
 function policyDelete(address _subject, string memory _resource, string memory _action) public{
require (msg.sender == owner);
require (SubjectPolicies[_subject][_resource][_action].isValued == true); 
delete SubjectPolicies[_subject][_resource][_action];
 }
 
 function registrationAdd (address _subject, uint _id) public {
 SubjectRegistration[_subject].id= _id;
 SubjectRegistration[_subject].isValued= true;
 }
 
 
function deleteACC() public{
require (msg.sender == owner);

}

function accessControl(address _subject, string memory _resource, string memory _action, uint _time) public {

uint8 errcode = 0;
uint penalty = 0;
uint s;

if (SubjectRegistration[_subject].isValued== false){//not registrated state
    errcode=1;
    
   }
   
else {// registrated state
    if (SubjectMisconductList[_subject].TimeofUnblock > _time){//still blocked state
        errcode=2;
       
       
    } 
    else{//unblocked state
    SubjectMisconductList[_subject].TimeofUnblock=0;
   
    
        if (keccak256(bytes(SubjectPolicies[_subject][_resource][_action].permission)) != (keccak256(bytes("allow")))){ //policycheck = false
            errcode=3;
              
        }
        else {//policycheck = true
            if ((_time - SubjectPolicies[_subject][_resource][_action].ToLR)<= (SubjectPolicies[_subject][_resource][_action].minInt)){ //frequent access
                SubjectPolicies[_subject][_resource][_action].NoFR++;
            
                if (SubjectPolicies[_subject][_resource][_action].NoFR>= SubjectPolicies[_subject][_resource][_action].Limit){
                //s= (SubjectPolicies[_subject][_resource][_action].NoFR - SubjectPolicies[_subject][_resource][_action].Limit) +1;
                s= SubjectMisconductList[_subject].mbs.length +1;
                penalty= s * 30;
            SubjectMisconductList[_subject].TimeofUnblock= _time + penalty  * 1 seconds;
                SubjectMisconductList[_subject].mbs.push(Misconduct(_resource,_action, _time, penalty));
                    errcode=4;
                    
        
                }
               
            }
            
          else {
        
             SubjectPolicies[_subject][_resource][_action].NoFR=0;
            
             
          }  
        }
    }
}
SubjectPolicies[_subject][_resource][_action].ToLR=_time;
if(0 == errcode) emit ReturnAccessResult(msg.sender, "Access authorized!", penalty, true, _time);
if(1 == errcode) emit ReturnAccessResult(msg.sender, "Authentication failure! Invalid Requester", penalty, false, _time);
if(2 == errcode) emit ReturnAccessResult(msg.sender, "Requests are still blocked!", penalty, false, _time);
if(3 == errcode) emit ReturnAccessResult(msg.sender, "Static Check failed!!",  penalty, false, _time);
if(4 == errcode) emit ReturnAccessResult(msg.sender, "Misbehavior detected! too frequent access", penalty, false, _time);

 }

     
 }
